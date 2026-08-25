/**
 * CloudSentinel — finding lifecycle.
 *
 * Decides what a new scan means for the findings already stored: which are new,
 * which are still open, which have come back, and which can honestly be called
 * resolved.
 *
 * Where it sits in the architecture: between the rule engine's stateless output
 * and the database. lib/db/scans.ts executes the plan this file produces.
 *
 *   ScanResult + stored findings --> [ planLifecycle ] --> LifecyclePlan --> SQL
 *
 * **This file contains no SQL and performs no I/O.** That is deliberate: the
 * lifecycle rules are the part of Phase 4 most likely to be subtly wrong, and
 * keeping them a pure function of two inputs means they can be exhaustively
 * tested in CI with no database running at all. Everything that touches
 * Postgres lives in lib/db/scans.ts and is comparatively mechanical.
 *
 * ## The problem this solves
 *
 * The rule engine recomputes everything from scratch on every run, so by itself
 * it can only answer "what is wrong right now". Matching findings across scans
 * turns that into "what is new, what is still open, what did we fix" — which is
 * the difference between a linter and a posture-management tool. Matching is
 * possible because finding ids are deterministic (see lib/rules/engine.ts).
 *
 * ## The rule that matters: absence is not proof
 *
 * The tempting implementation is "any stored finding not in this scan is
 * resolved". That is wrong, and wrong in the dangerous direction — it silently
 * closes real problems and reports success for work nobody did.
 *
 * A finding's absence only means it was fixed if this scan was actually in a
 * position to see it. So a stored finding is resolved **only** when all of
 * these hold:
 *
 *   1. The scan recorded no collection errors. A scan that could not see the
 *      whole environment cannot prove anything is absent from it.
 *   2. The rule that produced the finding ran in this scan. If a rule was
 *      removed or errored, its findings' absence says nothing.
 *   3. Either the resource was observed and the rule stayed quiet about it
 *      (`fixed`), or the resource is gone entirely (`resource_removed`).
 *
 * Anything else leaves the finding open. Leaving a fixed finding open costs
 * someone a few minutes of confusion; closing an unfixed one costs a breach, so
 * the asymmetry is resolved deliberately in that direction. It is the same
 * three-state honesty the rule engine applies to `inconclusive`, carried
 * through to storage.
 */

import type { Finding } from "../rules/types.ts";

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/**
 * The subset of a stored finding the lifecycle decision needs.
 *
 * Deliberately narrow — just the identity, current state, and origin. Passing
 * the whole database row would couple this pure logic to the table's column
 * names and make the tests tedious to write.
 */
export interface StoredFinding {
  id: string;
  ruleId: string;
  resourceId: string;
  status: "open" | "resolved";
}

/** Everything {@link planLifecycle} needs to know about the scan just completed. */
export interface ScanContext {
  /** Findings this scan produced, both `fail` and `inconclusive`. */
  findings: readonly Finding[];

  /**
   * Ids of every resource this scan collected.
   *
   * Distinguishes "the bucket is no longer public" from "the bucket no longer
   * exists". Both close the finding, but they are different events and a
   * compliance report that conflates them is easy to game — delete the
   * offending resource and every finding reads as fixed.
   */
  observedResourceIds: ReadonlySet<string>;

  /**
   * Ids of the rules that evaluated at least one resource in this scan.
   *
   * Taken from the engine's `ruleSummaries`, which only include rules that
   * actually ran. A rule that was deleted from the registry, or that matched
   * nothing, must not have its old findings closed on its behalf.
   */
  evaluatedRuleIds: ReadonlySet<string>;

  /**
   * Whether the underlying inventory had collection errors.
   *
   * When true, nothing is resolved at all. A partial scan is not evidence of
   * absence, and this is the single most important line of defence against the
   * tool reporting a clean environment it never managed to look at.
   */
  hadCollectionErrors: boolean;
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/** Why a finding stopped being reported. */
export type ResolutionReason = "fixed" | "resource_removed";

/** A stored finding this scan closes. */
export interface ResolvedFinding {
  id: string;
  reason: ResolutionReason;
}

/**
 * What lib/db/scans.ts should write, as a result of this scan.
 *
 * The four finding buckets are disjoint and together cover every finding in the
 * scan plus every previously-open stored finding.
 */
export interface LifecyclePlan {
  /** Never seen before. Inserted with `first_seen_at` set to this scan. */
  created: Finding[];

  /** Already open and still reported. `last_seen_at` moves forward. */
  continuing: Finding[];

  /**
   * Previously resolved, and reported again.
   *
   * Worth separating from `created` because it is a different and more
   * interesting event: a problem that was fixed and has come back usually means
   * the fix did not stick, or something is reverting configuration — a stronger
   * signal than a brand new finding.
   */
  reopened: Finding[];

  /** Previously open, absent from this scan, and safe to close. */
  resolved: ResolvedFinding[];

  /**
   * Previously open, absent from this scan, but NOT safe to close — because the
   * scan was partial or the rule did not run.
   *
   * Reported rather than silently ignored, so the CLI can say "3 findings could
   * not be re-checked" instead of leaving them quietly stale.
   */
  unverified: string[];
}

// ---------------------------------------------------------------------------
// The decision
// ---------------------------------------------------------------------------

/**
 * Works out what one scan means for the findings already stored.
 *
 * Pure: no I/O, no clock reads, no mutation of either input. The caller
 * supplies the timestamps when it writes, so that every row from one scan
 * shares exactly one time.
 *
 * @param stored - every finding currently in the database, both open and
 *   resolved. Resolved ones are needed to detect reopening.
 * @param scan - what the scan just produced. See {@link ScanContext}.
 * @returns the disjoint buckets of work to perform.
 */
export function planLifecycle(
  stored: readonly StoredFinding[],
  scan: ScanContext,
): LifecyclePlan {
  const storedById = new Map(stored.map((finding) => [finding.id, finding]));
  const currentIds = new Set(scan.findings.map((finding) => finding.id));

  const created: Finding[] = [];
  const continuing: Finding[] = [];
  const reopened: Finding[] = [];

  for (const finding of scan.findings) {
    const previous = storedById.get(finding.id);
    if (!previous) {
      created.push(finding);
    } else if (previous.status === "resolved") {
      reopened.push(finding);
    } else {
      continuing.push(finding);
    }
  }

  const resolved: ResolvedFinding[] = [];
  const unverified: string[] = [];

  for (const previous of stored) {
    // Only previously-open findings can be closed. A resolved one that is still
    // absent simply stays resolved.
    if (previous.status !== "open") continue;
    if (currentIds.has(previous.id)) continue;

    // Guard 1: a partial scan proves nothing about what is absent from it.
    if (scan.hadCollectionErrors) {
      unverified.push(previous.id);
      continue;
    }

    // Guard 2: the resource is gone.
    //
    // Checked before the rule guard, and deliberately so. When a resource has
    // been deleted, the evidence is the *collector's* — it completed without
    // error and did not return the resource — and no rule could have evaluated
    // it in any case. Requiring the rule to have run here would be incoherent,
    // and it would leave every finding on a deleted resource permanently
    // unverified: an environment emptied of buckets reports no S3 rules at all,
    // since a rule that matches nothing never appears in the scan's summaries.
    if (!scan.observedResourceIds.has(previous.resourceId)) {
      resolved.push({ id: previous.id, reason: "resource_removed" });
      continue;
    }

    // Guard 3: the resource is still there, so only the rule can say whether
    // the problem is gone. If it did not run — removed from the registry, or it
    // threw — its silence is not a verdict, and crediting a fix to a check that
    // never executed is exactly the false clean result this file exists to
    // prevent.
    if (!scan.evaluatedRuleIds.has(previous.ruleId)) {
      unverified.push(previous.id);
      continue;
    }

    // The resource was inspected and the rule stayed quiet about it: a real fix.
    resolved.push({ id: previous.id, reason: "fixed" });
  }

  return { created, continuing, reopened, resolved, unverified };
}

/**
 * Summarises a plan as a one-line sentence for CLI output.
 *
 * Ordered by what a reader cares about most: what is new, what came back, what
 * was fixed. Clauses with a count of zero are omitted, so a routine re-scan of
 * an unchanged environment reads as "no change" rather than as a row of zeros.
 */
export function describeLifecycle(plan: LifecyclePlan): string {
  const parts: string[] = [];
  if (plan.created.length > 0) parts.push(`${plan.created.length} new`);
  if (plan.reopened.length > 0) parts.push(`${plan.reopened.length} reopened`);
  if (plan.continuing.length > 0) {
    parts.push(`${plan.continuing.length} still open`);
  }
  if (plan.resolved.length > 0) parts.push(`${plan.resolved.length} resolved`);
  if (plan.unverified.length > 0) {
    parts.push(`${plan.unverified.length} could not be re-checked`);
  }
  return parts.length > 0 ? parts.join(", ") : "no change";
}
