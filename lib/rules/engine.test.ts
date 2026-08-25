/**
 * CloudSentinel — tests for the rule engine, including the Phase 3 contract.
 *
 * Run with `npm test`. Reads the committed `fixtures/inventory.json` snapshot,
 * so it needs no Docker, no LocalStack, and no credentials.
 *
 * This file does two jobs.
 *
 * 1. Unit tests for the engine's bookkeeping — dispatch, deterministic finding
 *    ids, counting, sorting, scoring, and the guarantee that one rule throwing
 *    cannot take down a whole scan.
 *
 * 2. The **Phase 3 contract test**. `scripts/seed-localstack.ts` promises
 *    thirteen specific findings in its `EXPECTED_FINDINGS` list, and promises
 *    that three named control resources are clean under every rule. This file
 *    asserts that running the real rule set over the real collected inventory
 *    produces exactly that. It is what makes the three halves of the project —
 *    the seeder, the collectors, and the rules — verifiably agree with each
 *    other instead of merely looking like they do.
 *
 *    The value of asserting the compliant controls produce *nothing* is easy to
 *    underrate. Any rule set can find problems if it is willing to shout at
 *    everything; the false-positive baseline is what makes the true positives
 *    worth reading.
 *
 * Regenerate the inventory snapshot after changing the seeder with:
 *
 *     npm run seed && npm run collect -- --out fixtures/inventory.json
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";

import type { Resource, ResourceInventory } from "../types/resource.ts";
import {
  ALL_RULES,
  computeRiskScore,
  countBySeverity,
  hasFindingAtOrAbove,
  runRules,
} from "./engine.ts";
import type { AnyRule, Finding, RuleVerdict } from "./types.ts";

const inventory = JSON.parse(
  readFileSync(
    join(import.meta.dirname, "..", "..", "fixtures", "inventory.json"),
    "utf8",
  ),
) as ResourceInventory;

// ---------------------------------------------------------------------------
// The Phase 3 contract
// ---------------------------------------------------------------------------

/**
 * The findings `scripts/seed-localstack.ts` promises, as `[resource, title]`.
 *
 * Duplicated here rather than imported, deliberately. The seeder is a script,
 * not a module: it calls `main()` at module scope, so importing it to read its
 * `EXPECTED_FINDINGS` constant would run the seeder — issuing writes against
 * whatever endpoint happened to be configured — every time the test suite ran.
 * A test that mutates cloud state as a side effect of being imported is not a
 * trade worth making, so the list is copied and this comment explains why. If
 * the two ever drift apart, this test fails with the exact title that no longer
 * matches, which is the outcome the duplication is meant to produce.
 */
const EXPECTED_FINDINGS: ReadonlyArray<readonly [resource: string, title: string]> = [
  ["cloudsentinel-public-assets", "S3 bucket has Block Public Access fully disabled"],
  ["cloudsentinel-public-assets", "S3 bucket policy grants s3:GetObject to Principal '*'"],
  ["cloudsentinel-public-assets", "S3 bucket ACL grants READ to AllUsers"],
  ["cloudsentinel-public-assets", "S3 bucket has versioning disabled"],
  ["cloudsentinel-public-assets", "S3 bucket has no server access logging"],
  ["cloudsentinel-open-mgmt", "Security group allows 0.0.0.0/0 on tcp/22 (SSH)"],
  ["cloudsentinel-open-mgmt", "Security group allows 0.0.0.0/0 on tcp/3389 (RDP)"],
  ["cloudsentinel-open-mgmt", "Security group allows ::/0 on tcp/22 (SSH over IPv6)"],
  ["cloudsentinel-admin-svc", "IAM user has an attached policy with Action '*' on Resource '*'"],
  ["cloudsentinel-admin-svc", "IAM user has an inline policy allowing unrestricted iam:PassRole"],
  ["cloudsentinel-admin-svc", "IAM user has console access but no MFA device"],
  ["cloudsentinel-admin-svc", "IAM user has a long-lived access key"],
  [
    "cloudsentinel-group-member",
    "IAM user inherits Action '*' on Resource '*' through group membership",
  ],
];

/**
 * The control resources the seeder promises are clean under every rule.
 *
 * These exist purely as a false-positive baseline. If a new rule starts firing
 * on one of them, either the rule is wrong or the control is no longer
 * compliant — and either way it needs a human decision, not a quietly updated
 * expectation.
 */
const COMPLIANT_RESOURCES = [
  "cloudsentinel-private-logs",
  "cloudsentinel-restricted-app",
  "cloudsentinel-readonly-svc",
];

describe("Phase 3 contract: seeded findings", () => {
  const result = runRules(inventory);

  test("the fixture inventory was collected without gaps", () => {
    // Every assertion below is meaningless if the snapshot came from a partial
    // scan, so this is checked first.
    assert.deepEqual(inventory.errors, []);
    for (const resource of inventory.resources) {
      assert.deepEqual(
        resource.unobserved,
        [],
        `${resource.name} has unobserved fields, so the fixture is incomplete`,
      );
    }
  });

  for (const [resourceName, title] of EXPECTED_FINDINGS) {
    test(`${resourceName}: ${title}`, () => {
      const match = result.findings.find(
        (finding) =>
          finding.resourceName === resourceName && finding.title === title,
      );
      assert.ok(
        match,
        `no finding titled "${title}" was reported for ${resourceName}. ` +
          `Findings for that resource: ${JSON.stringify(
            result.findings
              .filter((finding) => finding.resourceName === resourceName)
              .map((finding) => finding.title),
            null,
            2,
          )}`,
      );
      // A promised finding reported as inconclusive would mean the rule never
      // actually ran, which is not the same as detecting the problem.
      assert.equal(match.status, "fail");
    });
  }

  for (const resourceName of COMPLIANT_RESOURCES) {
    test(`${resourceName} produces no findings at all`, () => {
      const found = result.findings.filter(
        (finding) => finding.resourceName === resourceName,
      );
      assert.deepEqual(
        found.map((finding) => finding.title),
        [],
        `${resourceName} is a compliant control and must stay clean`,
      );
    });
  }

  test("the untouched default security group stays clean", () => {
    // Not a seeded control, but a real resource LocalStack creates on its own.
    // A rule that fires here would be firing on every VPC in a real account.
    assert.deepEqual(
      result.findings
        .filter((finding) => finding.resourceName === "default")
        .map((finding) => finding.title),
      [],
    );
  });

  test("reports the expected total, so a new rule cannot slip in unnoticed", () => {
    // Fourteen, not thirteen: the rule set legitimately finds one thing the
    // seeder does not list — `cloudsentinel-group-member` also inherits an
    // unrestricted iam:PassRole grant from the same legacy-admins group, via
    // that group's `iam:*` inline policy. It is a genuine privilege escalation
    // path and a genuine finding, so it is recorded here rather than suppressed.
    // Pinning the total means any future change to the rule set has to come
    // past this line and be explained.
    assert.equal(result.findings.length, 14);
    assert.equal(
      result.findings.filter((finding) => finding.status === "inconclusive").length,
      0,
    );
  });

  test("carries the inventory's provenance into the result", () => {
    // A findings report that cannot say what environment it looked at, and
    // when, is not evidence of anything.
    assert.equal(result.collectedAt, inventory.collectedAt);
    assert.equal(result.endpoint, inventory.endpoint);
    assert.equal(result.region, inventory.region);
    assert.equal(result.collectionErrors, 0);
  });

  test("dates findings from the collection, not from when the rules ran", () => {
    // Re-running the engine over last week's inventory must not make last
    // week's problems look like today's.
    for (const finding of result.findings) {
      assert.equal(finding.detectedAt, inventory.collectedAt);
    }
  });
});

// ---------------------------------------------------------------------------
// Rule set hygiene
// ---------------------------------------------------------------------------

describe("rule registry", () => {
  test("every rule id is unique", () => {
    // Ids are part of every finding's primary key, so a duplicate would make
    // two different checks indistinguishable in the database.
    const ids = ALL_RULES.map((rule) => rule.id);
    assert.deepEqual([...new Set(ids)].sort(), [...ids].sort());
  });

  test("every rule carries the metadata a finding needs", () => {
    for (const rule of ALL_RULES) {
      assert.ok(rule.title.length > 0, `${rule.id} has no title`);
      assert.ok(rule.description.length > 0, `${rule.id} has no description`);
      assert.ok(rule.benchmark.length > 0, `${rule.id} has no benchmark`);
      assert.ok(rule.remediation.length > 0, `${rule.id} has no remediation`);
    }
  });

  test("every rule id is prefixed with the service it checks", () => {
    const prefixes: Record<string, string> = {
      s3_bucket: "s3-",
      security_group: "ec2-",
      iam_user: "iam-",
    };
    for (const rule of ALL_RULES) {
      assert.ok(
        rule.id.startsWith(prefixes[rule.appliesTo]!),
        `${rule.id} should start with ${prefixes[rule.appliesTo]}`,
      );
    }
  });
});

// ---------------------------------------------------------------------------
// Engine bookkeeping
// ---------------------------------------------------------------------------

/** A minimal resource for the engine tests, with no real service semantics. */
function bareBucket(id: string): Resource {
  return {
    id,
    type: "s3_bucket",
    name: id,
    region: "us-east-1",
    tags: {},
    collectedAt: "2026-08-25T00:00:00.000Z",
    unobserved: [],
    config: {
      createdAt: null,
      publicAccessBlock: null,
      policy: null,
      policyRaw: null,
      aclGrants: [],
      versioning: "Disabled",
      loggingEnabled: false,
      loggingTargetBucket: null,
      encryptionAlgorithm: null,
    },
  };
}

/** Wraps resources in an inventory envelope. */
function inventoryOf(...resources: Resource[]): ResourceInventory {
  return {
    collectedAt: "2026-08-25T00:00:00.000Z",
    endpoint: "http://localhost:4566",
    region: "us-east-1",
    resources,
    errors: [],
  };
}

/**
 * Builds a stub rule with a fixed evaluate function.
 *
 * `evaluate` is typed against the broad {@link Resource} union rather than
 * `AnyRule["evaluate"]`, which is a union of three *function* types. TypeScript
 * cannot contextually type an object literal against a union of signatures, so
 * the shorter spelling would widen every `status: "pass"` in the tests below to
 * plain `string` and fail to compile. The single cast on the way out is
 * confined to this helper.
 */
function stubRule(
  id: string,
  evaluate: (resource: Resource) => RuleVerdict[],
  overrides: Partial<Omit<AnyRule, "evaluate">> = {},
): AnyRule {
  return {
    id,
    title: `stub ${id}`,
    description: "stub",
    severity: "medium",
    benchmark: "stub",
    remediation: "stub",
    appliesTo: "s3_bucket",
    evaluate,
    ...overrides,
  } as unknown as AnyRule;
}

describe("runRules", () => {
  test("skips resources of a type the rule does not apply to", () => {
    let calls = 0;
    const rule = stubRule(
      "s3-counter",
      () => {
        calls += 1;
        return [{ status: "pass" }];
      },
      { appliesTo: "iam_user" },
    );

    runRules(inventoryOf(bareBucket("a")), [rule]);
    assert.equal(calls, 0);
  });

  test("produces deterministic ids that survive a re-scan", () => {
    // This is what will let the dashboard track a finding's lifecycle instead
    // of inventing a fresh set of problems on every run.
    const first = runRules(inventory);
    const second = runRules(inventory);
    assert.deepEqual(
      first.findings.map((finding) => finding.id),
      second.findings.map((finding) => finding.id),
    );
  });

  test("includes the verdict key in the id only when there is one", () => {
    const result = runRules(inventoryOf(bareBucket("bucket-1")), [
      stubRule("s3-keyed", () => [
        { status: "fail", detail: "d" },
        { status: "fail", detail: "d", key: "second" },
      ]),
    ]);
    assert.deepEqual(
      result.findings.map((finding) => finding.id),
      ["s3-keyed|bucket-1", "s3-keyed|bucket-1|second"],
    );
  });

  test("lets a verdict override the rule's title and severity", () => {
    const result = runRules(inventoryOf(bareBucket("b")), [
      stubRule("s3-override", () => [
        { status: "fail", detail: "d", title: "custom", severity: "critical" },
      ]),
    ]);
    assert.equal(result.findings[0]?.title, "custom");
    assert.equal(result.findings[0]?.severity, "critical");
  });

  test("counts an empty verdict list as not-applicable, never as a pass", () => {
    // Padding pass counts with checks that never ran would make the coverage
    // numbers meaningless.
    const result = runRules(inventoryOf(bareBucket("b")), [
      stubRule("s3-na", () => []),
    ]);
    assert.deepEqual(result.ruleSummaries, []);
  });

  test("tallies passes, failures, and inconclusives per rule", () => {
    const result = runRules(
      inventoryOf(bareBucket("a"), bareBucket("b"), bareBucket("c")),
      [
        stubRule("s3-mixed", (resource) => {
          if (resource.name === "a") return [{ status: "pass" }];
          if (resource.name === "b") return [{ status: "fail", detail: "d" }];
          return [{ status: "inconclusive", detail: "d" }];
        }),
      ],
    );
    assert.deepEqual(result.ruleSummaries, [
      {
        ruleId: "s3-mixed",
        title: "stub s3-mixed",
        severity: "medium",
        evaluated: 3,
        passed: 1,
        failed: 1,
        inconclusive: 1,
      },
    ]);
  });

  test("counts a resource as clean only when no rule flagged it", () => {
    const result = runRules(inventoryOf(bareBucket("a"), bareBucket("b")), [
      stubRule("s3-half", (resource) =>
        resource.name === "a" ? [{ status: "fail", detail: "d" }] : [{ status: "pass" }],
      ),
    ]);
    assert.equal(result.resourcesScanned, 2);
    assert.equal(result.resourcesClean, 1);
  });

  test("turns a throwing rule into an inconclusive finding, not a crashed scan", () => {
    // Twelve rules times every resource in an account is a lot of surface for
    // one unexpected shape to crash on. Losing the eleven rules that worked
    // because the twelfth threw would be a poor trade.
    const result = runRules(inventoryOf(bareBucket("a")), [
      stubRule("s3-broken", () => {
        throw new Error("unexpected config shape");
      }),
      stubRule("s3-fine", () => [{ status: "fail", detail: "still ran" }]),
    ]);

    assert.equal(result.findings.length, 2);
    const broken = result.findings.find(
      (finding) => finding.ruleId === "s3-broken",
    );
    assert.equal(broken?.status, "inconclusive");
    assert.match(broken!.detail, /unexpected config shape/);
    // The other rule still produced its finding.
    assert.ok(result.findings.some((finding) => finding.ruleId === "s3-fine"));
  });

  test("sorts most severe first, failures before inconclusives", () => {
    const result = runRules(inventoryOf(bareBucket("a")), [
      stubRule("s3-low", () => [{ status: "fail", detail: "d", severity: "low" }], {
        severity: "low",
      }),
      stubRule(
        "s3-crit-unknown",
        () => [{ status: "inconclusive", detail: "d" }],
        { severity: "critical" },
      ),
      stubRule("s3-crit", () => [{ status: "fail", detail: "d" }], {
        severity: "critical",
      }),
    ]);

    assert.deepEqual(
      result.findings.map((finding) => finding.ruleId),
      ["s3-crit", "s3-crit-unknown", "s3-low"],
    );
  });
});

// ---------------------------------------------------------------------------
// Scoring and reporting helpers
// ---------------------------------------------------------------------------

/** Builds a finding carrying only the fields the scoring helpers read. */
function scored(
  severity: Finding["severity"],
  status: Finding["status"] = "fail",
): Finding {
  return {
    id: `${severity}-${status}`,
    ruleId: "stub",
    title: "stub",
    severity,
    status,
    benchmark: "stub",
    remediation: "stub",
    resourceId: "r",
    resourceName: "r",
    resourceType: "s3_bucket",
    region: "us-east-1",
    detail: "d",
    detectedAt: "2026-08-25T00:00:00.000Z",
  };
}

describe("computeRiskScore", () => {
  test("is zero for a clean scan", () => {
    assert.equal(computeRiskScore([]), 0);
  });

  test("never exceeds 100 however many findings there are", () => {
    const many = Array.from({ length: 500 }, () => scored("critical"));
    const score = computeRiskScore(many);
    assert.ok(score <= 100, `score was ${score}`);
    assert.ok(score > 90);
  });

  test("weights a critical finding far above a low one", () => {
    // A linear scale would let a pile of hygiene issues drown out the thing
    // that actually gets an account breached.
    assert.ok(computeRiskScore([scored("critical")]) > computeRiskScore([scored("low")]));
    assert.ok(
      computeRiskScore([scored("critical")]) >
        computeRiskScore(Array.from({ length: 5 }, () => scored("low"))),
    );
  });

  test("counts an inconclusive finding at half weight", () => {
    // Unknown risk is not the same as confirmed risk — but ignoring it would
    // let a scan that read nothing report a perfect score.
    const confirmed = computeRiskScore([scored("critical", "fail")]);
    const unknown = computeRiskScore([scored("critical", "inconclusive")]);
    assert.ok(unknown > 0);
    assert.ok(unknown < confirmed);
  });

  test("increases monotonically as findings accumulate", () => {
    let previous = 0;
    for (let count = 1; count <= 10; count += 1) {
      const score = computeRiskScore(
        Array.from({ length: count }, () => scored("high")),
      );
      assert.ok(score > previous, `score did not increase at ${count} findings`);
      previous = score;
    }
  });
});

describe("countBySeverity", () => {
  test("always returns all four keys so the dashboard can render fixed tiles", () => {
    assert.deepEqual(countBySeverity([]), {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    });
  });

  test("counts the fixture scan correctly", () => {
    const counts = countBySeverity(runRules(inventory).findings);
    assert.equal(
      counts.critical + counts.high + counts.medium + counts.low,
      runRules(inventory).findings.length,
    );
  });
});

describe("hasFindingAtOrAbove", () => {
  test("includes everything more severe than the threshold", () => {
    assert.equal(hasFindingAtOrAbove([scored("critical")], "high"), true);
    assert.equal(hasFindingAtOrAbove([scored("medium")], "high"), false);
    assert.equal(hasFindingAtOrAbove([scored("high")], "high"), true);
  });

  test("counts inconclusive findings toward the gate", () => {
    // A check that could not run is not evidence of compliance, so it must not
    // let a CI gate pass.
    assert.equal(
      hasFindingAtOrAbove([scored("critical", "inconclusive")], "critical"),
      true,
    );
  });

  test("is false for a clean scan at every threshold", () => {
    for (const severity of ["critical", "high", "medium", "low"] as const) {
      assert.equal(hasFindingAtOrAbove([], severity), false);
    }
  });
});
