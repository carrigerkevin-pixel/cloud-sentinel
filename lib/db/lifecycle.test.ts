/**
 * CloudSentinel — tests for the finding lifecycle.
 *
 * Run with `npm test`. Needs no database: lib/db/lifecycle.ts is a pure
 * function precisely so these rules can be tested exhaustively in CI, where
 * there is no Postgres.
 *
 * The tests are weighted toward the cases where getting it wrong is expensive.
 * Marking a finding resolved is a claim that a problem went away, and a scanner
 * that makes that claim wrongly is worse than one that never made it — the
 * dashboard turns green and nobody looks again. So most of what follows checks
 * the circumstances in which the code must *refuse* to resolve something:
 * a partial scan, a rule that did not run, a resource that vanished.
 */

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import type { Finding } from "../rules/types.ts";
import {
  describeLifecycle,
  planLifecycle,
  type ScanContext,
  type StoredFinding,
} from "./lifecycle.ts";

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

/** Builds a finding as the engine would emit it. */
function finding(id: string, overrides: Partial<Finding> = {}): Finding {
  const [ruleId = "rule-a", resourceId = "resource-a"] = id.split("|");
  return {
    id,
    ruleId,
    title: `finding ${id}`,
    severity: "critical",
    status: "fail",
    benchmark: "test",
    remediation: "fix it",
    resourceId,
    resourceName: resourceId,
    resourceType: "s3_bucket",
    region: "us-east-1",
    detail: "evidence",
    detectedAt: "2026-08-25T00:00:00.000Z",
    ...overrides,
  };
}

/** Builds a stored finding row. */
function storedFinding(
  id: string,
  status: "open" | "resolved" = "open",
): StoredFinding {
  const [ruleId = "rule-a", resourceId = "resource-a"] = id.split("|");
  return { id, ruleId, resourceId, status };
}

/**
 * Builds a scan context, defaulting to the healthy case: no collection errors,
 * and every rule and resource mentioned in `findings` treated as observed.
 *
 * Tests then override exactly the one thing they are about, so each test reads
 * as a statement of the condition it describes.
 */
function scanContext(
  findings: Finding[],
  overrides: Partial<ScanContext> = {},
): ScanContext {
  return {
    findings,
    observedResourceIds: new Set(findings.map((f) => f.resourceId)),
    evaluatedRuleIds: new Set(findings.map((f) => f.ruleId)),
    hadCollectionErrors: false,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// New, continuing, reopened
// ---------------------------------------------------------------------------

describe("planLifecycle — classifying reported findings", () => {
  test("a finding never seen before is created", () => {
    const plan = planLifecycle([], scanContext([finding("rule-a|resource-a")]));
    assert.deepEqual(
      plan.created.map((f) => f.id),
      ["rule-a|resource-a"],
    );
    assert.deepEqual(plan.continuing, []);
    assert.deepEqual(plan.reopened, []);
  });

  test("a finding already open and still reported is continuing", () => {
    // The first-seen date must not move, which is what makes "public since the
    // 4th of August" answerable at all. Continuing findings only ever advance
    // last_seen_at.
    const plan = planLifecycle(
      [storedFinding("rule-a|resource-a", "open")],
      scanContext([finding("rule-a|resource-a")]),
    );
    assert.deepEqual(
      plan.continuing.map((f) => f.id),
      ["rule-a|resource-a"],
    );
    assert.deepEqual(plan.created, []);
  });

  test("a resolved finding that comes back is reopened, not created", () => {
    // A problem that was fixed and returned is a stronger signal than a new
    // one: it usually means the fix did not stick or something is reverting
    // configuration. Folding it into `created` would hide that.
    const plan = planLifecycle(
      [storedFinding("rule-a|resource-a", "resolved")],
      scanContext([finding("rule-a|resource-a")]),
    );
    assert.deepEqual(
      plan.reopened.map((f) => f.id),
      ["rule-a|resource-a"],
    );
    assert.deepEqual(plan.created, []);
    assert.deepEqual(plan.resolved, []);
  });

  test("the buckets are disjoint and cover every reported finding", () => {
    const plan = planLifecycle(
      [
        storedFinding("rule-a|r1", "open"),
        storedFinding("rule-a|r2", "resolved"),
      ],
      scanContext([
        finding("rule-a|r1"),
        finding("rule-a|r2"),
        finding("rule-a|r3"),
      ]),
    );
    assert.deepEqual(plan.continuing.map((f) => f.id), ["rule-a|r1"]);
    assert.deepEqual(plan.reopened.map((f) => f.id), ["rule-a|r2"]);
    assert.deepEqual(plan.created.map((f) => f.id), ["rule-a|r3"]);
  });
});

// ---------------------------------------------------------------------------
// Resolution — the cases that matter
// ---------------------------------------------------------------------------

describe("planLifecycle — resolving", () => {
  test("an open finding whose resource was checked and is now clean is fixed", () => {
    const plan = planLifecycle(
      [storedFinding("rule-a|resource-a", "open")],
      // The rule ran and the resource was seen; the rule simply had nothing to
      // say about it this time.
      scanContext([], {
        observedResourceIds: new Set(["resource-a"]),
        evaluatedRuleIds: new Set(["rule-a"]),
      }),
    );
    assert.deepEqual(plan.resolved, [
      { id: "rule-a|resource-a", reason: "fixed" },
    ]);
    assert.deepEqual(plan.unverified, []);
  });

  test("an open finding whose resource no longer exists is resource_removed", () => {
    // Deleting a public bucket does close the finding, but it is not the same
    // event as making it private. A compliance report that cannot tell them
    // apart can be gamed by deleting the evidence.
    const plan = planLifecycle(
      [storedFinding("rule-a|resource-a", "open")],
      scanContext([], {
        observedResourceIds: new Set(),
        evaluatedRuleIds: new Set(["rule-a"]),
      }),
    );
    assert.deepEqual(plan.resolved, [
      { id: "rule-a|resource-a", reason: "resource_removed" },
    ]);
  });

  test("NOTHING is resolved when the scan had collection errors", () => {
    // The single most important guard in this file. A scan that could not see
    // the whole environment cannot prove anything is absent from it, and
    // closing findings on that basis would turn a failed scan into a clean
    // bill of health.
    const plan = planLifecycle(
      [
        storedFinding("rule-a|r1", "open"),
        storedFinding("rule-a|r2", "open"),
      ],
      scanContext([], {
        observedResourceIds: new Set(["r1", "r2"]),
        evaluatedRuleIds: new Set(["rule-a"]),
        hadCollectionErrors: true,
      }),
    );
    assert.deepEqual(plan.resolved, []);
    assert.deepEqual(plan.unverified.sort(), ["rule-a|r1", "rule-a|r2"]);
  });

  test("resolves a deleted resource even though no rule could evaluate it", () => {
    // Regression test. An environment emptied of buckets reports no S3 rules at
    // all — a rule that matches nothing never appears in the scan's summaries —
    // so an over-eager "did the rule run?" guard left every finding on a deleted
    // resource permanently unverified. The collector's clean, complete run is
    // the evidence here, not any rule's silence.
    const plan = planLifecycle(
      [storedFinding("rule-a|resource-a", "open")],
      scanContext([], {
        observedResourceIds: new Set(),
        evaluatedRuleIds: new Set(),
      }),
    );
    assert.deepEqual(plan.resolved, [
      { id: "rule-a|resource-a", reason: "resource_removed" },
    ]);
    assert.deepEqual(plan.unverified, []);
  });

  test("a finding is not resolved when its rule did not run", () => {
    // A rule that was removed from the registry, or that threw, says nothing
    // about its old findings. Closing them would credit a fix to a check that
    // never executed.
    const plan = planLifecycle(
      [storedFinding("rule-gone|resource-a", "open")],
      scanContext([], {
        observedResourceIds: new Set(["resource-a"]),
        evaluatedRuleIds: new Set(["rule-a"]),
      }),
    );
    assert.deepEqual(plan.resolved, []);
    assert.deepEqual(plan.unverified, ["rule-gone|resource-a"]);
  });

  test("an already-resolved finding that stays absent is left alone", () => {
    // It must not be resolved a second time, which would overwrite the original
    // resolution date and lose when the fix actually happened.
    const plan = planLifecycle(
      [storedFinding("rule-a|resource-a", "resolved")],
      scanContext([], {
        observedResourceIds: new Set(["resource-a"]),
        evaluatedRuleIds: new Set(["rule-a"]),
      }),
    );
    assert.deepEqual(plan.resolved, []);
    assert.deepEqual(plan.unverified, []);
  });

  test("an inconclusive finding keeps the problem open rather than resolving it", () => {
    // "We could not check" is not "it is fixed". The finding is still reported
    // by this scan, so it continues — the conservative reading, and the same
    // three-state honesty the rule engine applies.
    const plan = planLifecycle(
      [storedFinding("rule-a|resource-a", "open")],
      scanContext([
        finding("rule-a|resource-a", { status: "inconclusive" }),
      ]),
    );
    assert.deepEqual(plan.resolved, []);
    assert.deepEqual(
      plan.continuing.map((f) => f.id),
      ["rule-a|resource-a"],
    );
  });

  test("resolves one finding while leaving another open on the same resource", () => {
    // Closing SSH must not mark the RDP finding on the same security group
    // fixed. This is why findings are keyed per problem rather than per
    // resource.
    const plan = planLifecycle(
      [
        storedFinding("ec2-ingress|sg-1", "open"),
        storedFinding("ec2-ingress-rdp|sg-1", "open"),
      ],
      scanContext([finding("ec2-ingress-rdp|sg-1")], {
        observedResourceIds: new Set(["sg-1"]),
        evaluatedRuleIds: new Set(["ec2-ingress", "ec2-ingress-rdp"]),
      }),
    );
    assert.deepEqual(plan.resolved, [
      { id: "ec2-ingress|sg-1", reason: "fixed" },
    ]);
    assert.deepEqual(
      plan.continuing.map((f) => f.id),
      ["ec2-ingress-rdp|sg-1"],
    );
  });
});

// ---------------------------------------------------------------------------
// Whole-scan behaviour
// ---------------------------------------------------------------------------

describe("planLifecycle — whole scans", () => {
  test("a first scan creates everything and resolves nothing", () => {
    const plan = planLifecycle(
      [],
      scanContext([finding("rule-a|r1"), finding("rule-b|r2")]),
    );
    assert.equal(plan.created.length, 2);
    assert.deepEqual(plan.resolved, []);
    assert.deepEqual(plan.unverified, []);
  });

  test("an unchanged re-scan changes nothing", () => {
    // The common case, and the one that must be quiet. Re-scanning an
    // unchanged environment should not manufacture activity — that is what the
    // deterministic finding ids buy.
    const findings = [finding("rule-a|r1"), finding("rule-b|r2")];
    const plan = planLifecycle(
      [storedFinding("rule-a|r1"), storedFinding("rule-b|r2")],
      scanContext(findings),
    );
    assert.deepEqual(plan.created, []);
    assert.deepEqual(plan.reopened, []);
    assert.deepEqual(plan.resolved, []);
    assert.equal(plan.continuing.length, 2);
    assert.equal(describeLifecycle(plan), "2 still open");
  });

  test("an empty scan of an empty environment is a no-op", () => {
    const plan = planLifecycle([], scanContext([]));
    assert.equal(describeLifecycle(plan), "no change");
  });

  test("does not mutate either input", () => {
    // The caller reuses both, and a plan that quietly edited the stored list
    // would corrupt the writes that follow it.
    const stored = [storedFinding("rule-a|r1")];
    const storedCopy = structuredClone(stored);
    const findings = [finding("rule-a|r1")];
    const findingsCopy = structuredClone(findings);

    planLifecycle(stored, scanContext(findings));

    assert.deepEqual(stored, storedCopy);
    assert.deepEqual(findings, findingsCopy);
  });
});

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

describe("describeLifecycle", () => {
  test("omits zero counts so a quiet scan reads as quiet", () => {
    const plan = planLifecycle([], scanContext([finding("rule-a|r1")]));
    assert.equal(describeLifecycle(plan), "1 new");
  });

  test("leads with what a reader cares about most", () => {
    const plan = planLifecycle(
      [
        storedFinding("rule-a|r1", "open"),
        storedFinding("rule-a|r2", "resolved"),
        storedFinding("rule-a|r3", "open"),
      ],
      scanContext([finding("rule-a|r1"), finding("rule-a|r2"), finding("rule-a|r4")], {
        observedResourceIds: new Set(["r1", "r2", "r3", "r4"]),
        evaluatedRuleIds: new Set(["rule-a"]),
      }),
    );
    assert.equal(
      describeLifecycle(plan),
      "1 new, 1 reopened, 1 still open, 1 resolved",
    );
  });

  test("surfaces findings that could not be re-checked", () => {
    const plan = planLifecycle(
      [storedFinding("rule-a|r1", "open")],
      scanContext([], { hadCollectionErrors: true }),
    );
    assert.equal(describeLifecycle(plan), "1 could not be re-checked");
  });
});
