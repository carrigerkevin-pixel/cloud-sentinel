/**
 * CloudSentinel — rule engine.
 *
 * The runner that takes a {@link ResourceInventory} from the collectors, walks
 * every registered rule over every applicable resource, and turns the resulting
 * verdicts into a {@link ScanResult}. This is stage two of the pipeline and the
 * heart of the tool.
 *
 *   inventory.json --> [ runRules ] --> ScanResult { findings, summaries, score }
 *                            ^
 *                            +-- ALL_RULES (S3_RULES + EC2_RULES + IAM_RULES)
 *
 * Entry point: `npm run scan` (scripts/scan.ts). This module has no CLI of its
 * own and no I/O at all — it is a pure function from an inventory to a result,
 * which is what lets the whole engine be tested against a committed fixture
 * with no Docker, no LocalStack, and no credentials.
 *
 * The engine is deliberately thin. All security judgement lives in the rule
 * modules; everything here is bookkeeping — dispatch, id construction,
 * counting, sorting, scoring. Keeping it that way means a new check is one
 * object added to one array, with no engine changes, and it means a bug in the
 * engine cannot silently change what a rule decided.
 *
 * One thing the engine does insist on: a rule that throws is caught and
 * converted into an inconclusive finding rather than being allowed to abort the
 * scan. Twelve rules times every resource in an account is a lot of surface for
 * one unexpected `null` to crash on, and losing an entire scan — including the
 * eleven rules that worked — because one rule met a config shape it did not
 * anticipate would be a poor trade. The failure is still reported, loudly, as a
 * gap in coverage.
 */

import type { Resource, ResourceInventory } from "../types/resource.ts";
import { EC2_RULES } from "./ec2.ts";
import { IAM_RULES } from "./iam.ts";
import { S3_RULES } from "./s3.ts";
import { SEVERITY_ORDER, SEVERITY_WEIGHT } from "./types.ts";
import type {
  AnyRule,
  Finding,
  RuleSummary,
  RuleVerdict,
  ScanResult,
  Severity,
} from "./types.ts";

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/**
 * Every rule CloudSentinel knows about.
 *
 * The single place a new check is registered. Ordered by service so that the
 * default report groups the way someone would read it, and so `npm run scan
 * --rules` prints a stable list.
 *
 * Twelve rules covering the three services the collectors understand. Each one
 * documents the benchmark control it implements in its own definition; see
 * lib/rules/types.ts on how those references should be treated.
 */
export const ALL_RULES: readonly AnyRule[] = [
  ...S3_RULES,
  ...EC2_RULES,
  ...IAM_RULES,
];

// ---------------------------------------------------------------------------
// Finding construction
// ---------------------------------------------------------------------------

/**
 * Builds the deterministic id for a finding.
 *
 * Format: `<ruleId>|<resourceId>|<key>`, with the key omitted when the rule
 * produced only one verdict for the resource. The pipe is used as the separator
 * because ARNs are full of colons and slashes, so a colon-separated id would be
 * ambiguous to split back apart.
 *
 * Determinism is the whole point. Re-scanning an unchanged environment must
 * produce the same ids, because that is what will let the dashboard say "this
 * finding was first seen three weeks ago and is still open" rather than
 * inventing a fresh set of problems on every run and losing every triage
 * decision along with them.
 */
function findingId(ruleId: string, resourceId: string, key?: string): string {
  return key === undefined
    ? `${ruleId}|${resourceId}`
    : `${ruleId}|${resourceId}|${key}`;
}

/**
 * Converts one non-passing verdict into a {@link Finding}.
 *
 * Rule metadata (severity, benchmark, remediation) is copied in rather than
 * referenced by rule id so the finding stays readable on its own after it has
 * been serialized to JSON or stored in Postgres — see the note on
 * {@link Finding}.
 *
 * @param rule - the rule that produced the verdict.
 * @param resource - the resource it was evaluated against.
 * @param verdict - a `fail` or `inconclusive` verdict. Passing a `pass` verdict
 *   is a programming error and is filtered out by the caller.
 * @param collectedAt - the inventory's timestamp, used as the finding's
 *   `detectedAt` so a finding always dates from when the environment was
 *   observed rather than when the rules happened to be run.
 */
function toFinding(
  rule: AnyRule,
  resource: Resource,
  verdict: Exclude<RuleVerdict, { status: "pass" }>,
  collectedAt: string,
): Finding {
  // An inconclusive verdict keeps the rule's severity so that "we could not
  // check whether this bucket is public" sorts alongside the public-bucket
  // findings rather than at the bottom of the report. A gap in coverage on a
  // critical check is itself a critical problem.
  const severity: Severity =
    verdict.status === "fail" ? (verdict.severity ?? rule.severity) : rule.severity;

  return {
    id: findingId(rule.id, resource.id, verdict.key),
    ruleId: rule.id,
    title: verdict.status === "fail" ? (verdict.title ?? rule.title) : rule.title,
    severity,
    status: verdict.status,
    benchmark: rule.benchmark,
    remediation: rule.remediation,
    resourceId: resource.id,
    resourceName: resource.name,
    resourceType: resource.type,
    region: resource.region,
    detail: verdict.detail,
    detectedAt: collectedAt,
  };
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

/**
 * Reduces a set of findings to a single 0-100 risk score for the dashboard's
 * headline number.
 *
 * How it works: each finding contributes its severity weight (see
 * `SEVERITY_WEIGHT` in lib/rules/types.ts), the weights are summed, and the sum
 * is mapped onto 0-100 through a saturating curve — `100 * total / (total + K)`.
 * The curve matters more than the constant. A linear score would hit 100 after
 * a handful of findings and then stop conveying anything, so an account with
 * three critical problems and an account with sixty would look identical. The
 * saturating form keeps every additional finding moving the number while making
 * each one move it less, which is roughly how the marginal risk actually
 * behaves.
 *
 * Inconclusive findings count at half weight. They represent unknown risk
 * rather than confirmed risk, so ignoring them would let a scan that failed to
 * read anything report a perfect score — but counting them in full would make
 * a permissions problem look identical to a breach.
 *
 * What this number is NOT: a measurement, a percentage of anything, or
 * comparable across environments of different sizes. It is a heuristic for
 * tracking one environment's own trend over time, and it should never be the
 * only thing anyone looks at. The findings list is the actual output; this is a
 * convenience on top of it.
 *
 * @param findings - every finding from the scan.
 * @returns an integer from 0 (nothing found) to 100.
 */
export function computeRiskScore(findings: readonly Finding[]): number {
  // Chosen so that a single critical finding (weight 40) lands near 40/100 and
  // a handful of mediums stays in the 20s — a scale that matches how a reviewer
  // would describe the same environment out loud.
  const HALF_SATURATION = 60;

  const total = findings.reduce((sum, finding) => {
    const weight = SEVERITY_WEIGHT[finding.severity];
    return sum + (finding.status === "inconclusive" ? weight / 2 : weight);
  }, 0);

  if (total === 0) return 0;
  return Math.round((100 * total) / (total + HALF_SATURATION));
}

// ---------------------------------------------------------------------------
// Sorting
// ---------------------------------------------------------------------------

/** Position of a severity in {@link SEVERITY_ORDER}, for comparison. */
function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

/**
 * Orders findings the way someone triaging them would want to read: most severe
 * first, confirmed failures ahead of inconclusive ones at the same severity,
 * then grouped by resource so everything wrong with one bucket appears
 * together, and finally by id so the order is fully deterministic.
 *
 * That last tiebreak is not cosmetic. Without it, two scans of an unchanged
 * environment could emit the same findings in a different order, and any
 * diff-based comparison of two reports would be full of spurious movement.
 */
function compareFindings(a: Finding, b: Finding): number {
  const bySeverity = severityRank(a.severity) - severityRank(b.severity);
  if (bySeverity !== 0) return bySeverity;

  if (a.status !== b.status) return a.status === "fail" ? -1 : 1;

  const byResource = a.resourceId.localeCompare(b.resourceId);
  if (byResource !== 0) return byResource;

  return a.id.localeCompare(b.id);
}

// ---------------------------------------------------------------------------
// The runner
// ---------------------------------------------------------------------------

/**
 * Runs every rule over every resource in an inventory.
 *
 * Pure: no I/O, no clock reads other than the single `scannedAt` stamp, and no
 * mutation of the inventory. Calling it twice on the same inventory produces
 * identical findings with identical ids.
 *
 * @param inventory - a collected inventory, from `npm run collect` or from a
 *   committed fixture.
 * @param rules - the rules to run. Defaults to {@link ALL_RULES}; overridden in
 *   tests to exercise one rule in isolation.
 * @returns the complete scan result, with findings sorted most severe first.
 *
 * Does not throw. A rule that throws is caught and reported as an inconclusive
 * finding against the resource it failed on, so one broken rule degrades
 * coverage instead of destroying the scan — see the file header.
 */
export function runRules(
  inventory: ResourceInventory,
  rules: readonly AnyRule[] = ALL_RULES,
): ScanResult {
  const findings: Finding[] = [];
  const summaries = new Map<string, RuleSummary>();

  for (const rule of rules) {
    const summary: RuleSummary = {
      ruleId: rule.id,
      title: rule.title,
      severity: rule.severity,
      evaluated: 0,
      passed: 0,
      failed: 0,
      inconclusive: 0,
    };

    for (const resource of inventory.resources) {
      if (resource.type !== rule.appliesTo) continue;

      let verdicts: RuleVerdict[];
      try {
        // The one cast in the engine. `rule.appliesTo` and `resource.type` have
        // just been compared, so the resource genuinely is the variant this
        // rule's `evaluate` expects — but TypeScript cannot connect a runtime
        // comparison on one object to the generic parameter of another, so the
        // relationship has to be asserted here rather than proven. It is
        // isolated to this single line precisely so the rest of the engine and
        // every rule body stay fully type-checked.
        const evaluate = rule.evaluate as (r: Resource) => RuleVerdict[];
        verdicts = evaluate(resource);
      } catch (error) {
        verdicts = [
          {
            status: "inconclusive",
            key: "rule-error",
            detail:
              `Rule "${rule.id}" threw while evaluating this resource, so the ` +
              "check did not run: " +
              (error instanceof Error ? error.message : String(error)),
          },
        ];
      }

      // An empty array means the rule did not apply to this resource at all
      // (an MFA check against a user with no console password, say). That is
      // not a pass and must not be counted as one — inflating pass counts with
      // checks that never ran would make the coverage numbers meaningless.
      if (verdicts.length === 0) continue;

      summary.evaluated += 1;
      for (const verdict of verdicts) {
        if (verdict.status === "pass") {
          summary.passed += 1;
          continue;
        }
        if (verdict.status === "fail") summary.failed += 1;
        else summary.inconclusive += 1;

        findings.push(toFinding(rule, resource, verdict, inventory.collectedAt));
      }
    }

    // Rules that matched no resource at all are left out of the report
    // entirely: listing "0 evaluated, 0 passed" for every S3 rule in an
    // account with no buckets is noise that hides the rules that did run.
    if (summary.evaluated > 0) summaries.set(rule.id, summary);
  }

  findings.sort(compareFindings);

  const flagged = new Set(findings.map((finding) => finding.resourceId));

  return {
    scannedAt: new Date().toISOString(),
    collectedAt: inventory.collectedAt,
    endpoint: inventory.endpoint,
    region: inventory.region,
    findings,
    ruleSummaries: [...summaries.values()],
    resourcesScanned: inventory.resources.length,
    resourcesClean: inventory.resources.filter(
      (resource) => !flagged.has(resource.id),
    ).length,
    riskScore: computeRiskScore(findings),
    // Carried forward so a report with no findings still shows whether the
    // scan could actually see everything. "Nothing found" and "nothing looked"
    // must never render identically.
    collectionErrors: inventory.errors.length,
  };
}

// ---------------------------------------------------------------------------
// Reporting helpers
// ---------------------------------------------------------------------------

/**
 * Counts findings by severity, for the report header and the dashboard's
 * summary tiles.
 *
 * Always returns all four keys, including zeros, so a caller can render a fixed
 * set of tiles without checking for missing entries.
 */
export function countBySeverity(
  findings: readonly Finding[],
): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

/**
 * Whether a scan contains any finding at or above a severity threshold.
 *
 * Backs the `--fail-on` flag in scripts/scan.ts, which is what makes this
 * usable as a CI gate: a pipeline can block a deploy on a new critical finding
 * while tolerating the medium-severity backlog it already knows about.
 *
 * Confirmed failures and inconclusive results both count. A check that could
 * not run is not evidence of compliance, and letting a scan pass its gate
 * because the thing it was supposed to check was unreadable would defeat the
 * point of having the gate.
 *
 * @param findings - the scan's findings.
 * @param threshold - the least-severe level that should trip the gate.
 */
export function hasFindingAtOrAbove(
  findings: readonly Finding[],
  threshold: Severity,
): boolean {
  const limit = severityRank(threshold);
  return findings.some((finding) => severityRank(finding.severity) <= limit);
}
