/**
 * CloudSentinel — integration tests for the dashboard queries and triage.
 *
 * Run with `npm run test:db`. **Requires a running PostgreSQL server.**
 *
 * What these cover that no unit test can. The queries in lib/db/dashboard.ts
 * and the transaction in lib/db/triage.ts are almost entirely SQL, and the
 * properties that matter about them are properties of the SQL:
 *
 *   - a suppressed finding leaves the default list but stays in the totals;
 *   - triage never writes to `findings.status`;
 *   - the state change and its audit entry are one transaction;
 *   - the audit trail survives the actor's account being deleted;
 *   - `inconclusive` is counted from the *latest* occurrence, not any of them.
 *
 * Every one of those is a claim about a join, a CHECK constraint, or a foreign
 * key action. Mocking the database would test the mock.
 *
 * ## Isolation
 *
 * Creates and drops its own database, named differently from the other
 * `.dbtest.ts` files because `node --test` runs test files concurrently — two
 * files sharing a database name would tear each other's schema down mid-run.
 */

import assert from "node:assert/strict";
import { after, before, beforeEach, describe, test } from "node:test";

import { Pool } from "pg";

import { runRules } from "../rules/engine.ts";
import type {
  Resource,
  ResourceInventory,
  S3BucketResource,
} from "../types/resource.ts";
import { loadEnvFile } from "../util/env.ts";
import { closePool, query } from "./client.ts";
import { dashboardSummary, findingDetail, listFindings, scanHistory } from "./dashboard.ts";
import { runMigrations } from "./migrate.ts";
import { saveScan } from "./scans.ts";
import {
  getTriage,
  setTriage,
  triageCounts,
  triageHistory,
  TriageValidationError,
  UnknownFindingError,
} from "./triage.ts";
import { createUser, deleteUser, type User } from "./users.ts";

/** Name of the throwaway database these tests create and drop. */
const TEST_DATABASE = "cloudsentinel_dashtest";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** A bucket that trips several of the S3 rules, including critical ones. */
function publicBucket(): S3BucketResource {
  return {
    id: "arn:aws:s3:::test-public",
    type: "s3_bucket",
    name: "test-public",
    region: "us-east-1",
    tags: {},
    collectedAt: "2026-08-01T00:00:00.000Z",
    unobserved: [],
    config: {
      createdAt: "2026-01-01T00:00:00.000Z",
      publicAccessBlock: null,
      policy: null,
      policyRaw: null,
      aclGrants: [],
      versioning: "Disabled",
      loggingEnabled: false,
      loggingTargetBucket: null,
      encryptionAlgorithm: "AES256",
    },
  };
}

/**
 * The same bucket, but with the public-access setting *unreadable*.
 *
 * Produces `inconclusive` verdicts rather than failures, which is what the
 * inconclusive counting test needs. The `unobserved` list is the collector's
 * way of saying "I could not look at this", and the rules honour it.
 */
function unreadableBucket(): S3BucketResource {
  const bucket = publicBucket();
  bucket.unobserved = ["publicAccessBlock"];
  return bucket;
}

function inventoryOf(
  resources: Resource[],
  collectedAt: string,
  errors: ResourceInventory["errors"] = [],
): ResourceInventory {
  return {
    collectedAt,
    endpoint: "http://localhost:4566",
    region: "us-east-1",
    resources: resources.map((resource) => ({ ...resource, collectedAt })),
    errors,
  };
}

/** Collects, runs the rules, and stores the result. */
async function scanAndSave(inventory: ResourceInventory) {
  return saveScan(inventory, runRules(inventory));
}

function adminPool(): Pool {
  return new Pool({
    host: process.env.POSTGRES_HOST ?? "127.0.0.1",
    port: Number(process.env.POSTGRES_PORT ?? 5432),
    user: process.env.POSTGRES_USER ?? "cloudsentinel",
    password: process.env.POSTGRES_PASSWORD,
    database: "postgres",
  });
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

before(async () => {
  loadEnvFile();

  const admin = adminPool();
  try {
    await admin.query(`DROP DATABASE IF EXISTS ${TEST_DATABASE}`);
    await admin.query(`CREATE DATABASE ${TEST_DATABASE}`);
  } finally {
    await admin.end();
  }

  process.env.POSTGRES_DB = TEST_DATABASE;
  process.env.DATABASE_URL = "";

  await runMigrations();
});

/** An admin to attribute triage decisions to. Recreated per test. */
let actor: User;

beforeEach(async () => {
  await query(
    "TRUNCATE triage_events, finding_triage, finding_occurrences, findings, resources, scans, users RESTART IDENTITY CASCADE",
  );
  actor = await createUser(
    "dash-test@example.invalid",
    "a-long-enough-test-passphrase",
    "admin",
  );
});

after(async () => {
  await closePool();

  const admin = adminPool();
  try {
    await admin.query(`DROP DATABASE IF EXISTS ${TEST_DATABASE}`);
  } finally {
    await admin.end();
  }
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

describe("dashboardSummary", () => {
  test("reports nothing when no scan has been saved", async () => {
    const summary = await dashboardSummary();

    // Must not render as a clean environment: no data and a clean environment
    // are different things, and the page says so.
    assert.equal(summary.latestScan, null);
    assert.deepEqual(summary.totalBySeverity, {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    });
  });

  test("carries the latest scan's provenance and risk score", async () => {
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));
    const summary = await dashboardSummary();

    assert.ok(summary.latestScan);
    assert.equal(summary.latestScan.endpoint, "http://localhost:4566");
    assert.equal(summary.latestScan.region, "us-east-1");
    assert.ok(summary.latestScan.riskScore > 0);
  });

  test("counts findings first seen by the latest scan", async () => {
    const first = await scanAndSave(
      inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"),
    );
    const created = first.plan.created.length;
    assert.ok(created > 0);
    assert.equal((await dashboardSummary()).newInLatestScan, created);

    // Re-scanning the same environment creates nothing new, and the count must
    // drop to zero rather than repeating the original figure.
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-02T00:00:00.000Z"));
    assert.equal((await dashboardSummary()).newInLatestScan, 0);
  });

  test("counts inconclusive from the latest occurrence only", async () => {
    // First scan: readable, so the rules fail outright.
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));
    assert.equal((await dashboardSummary()).inconclusive, 0);

    // Second scan: the setting could not be read. The same findings are now
    // inconclusive, and the count must reflect the *latest* verdict rather than
    // counting any occurrence that was ever inconclusive.
    await scanAndSave(
      inventoryOf([unreadableBucket()], "2026-08-02T00:00:00.000Z"),
    );
    assert.ok((await dashboardSummary()).inconclusive > 0);

    // Third scan: readable again. The count must go back down.
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-03T00:00:00.000Z"));
    assert.equal((await dashboardSummary()).inconclusive, 0);
  });
});

// ---------------------------------------------------------------------------
// The property the whole triage design rests on
// ---------------------------------------------------------------------------

describe("suppression", () => {
  test("hides a finding from lists but never from the totals", async () => {
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));

    const before = await dashboardSummary();
    const target = (await listFindings({ limit: 1 })).items[0]!;
    const severity = target.severity as keyof typeof before.totalBySeverity;

    await setTriage(
      target.id,
      "suppressed",
      "Accepted risk for the purposes of this test.",
      actor,
    );

    const after = await dashboardSummary();

    // The displayed count drops by one...
    assert.equal(
      after.openBySeverity[severity],
      before.openBySeverity[severity] - 1,
    );
    // ...the true total does not move...
    assert.equal(after.totalBySeverity[severity], before.totalBySeverity[severity]);
    // ...and the amount hidden is reported plainly.
    assert.equal(after.hidden.suppressed, 1);
  });

  test("never changes findings.status", async () => {
    // The single most important assertion in this file. If suppressing a
    // finding marked it resolved, CloudSentinel would report a bucket as fixed
    // because somebody clicked a button, and every report it produced would be
    // worthless.
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));
    const target = (await listFindings({ limit: 1 })).items[0]!;

    for (const state of ["acknowledged", "suppressed", "false_positive"] as const) {
      await setTriage(target.id, state, "Justified for the test.", actor);

      const [row] = await query<{ status: string; resolved_at: Date | null }>(
        "SELECT status, resolved_at FROM findings WHERE id = $1",
        [target.id],
      );
      assert.equal(row!.status, "open", `${state} must not resolve the finding`);
      assert.equal(row!.resolved_at, null);
    }
  });

  test("leaves the finding retrievable by filtering for its state", async () => {
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));
    const target = (await listFindings({ limit: 1 })).items[0]!;
    await setTriage(target.id, "suppressed", "Accepted.", actor);

    // Hidden by default...
    const defaultList = await listFindings({ limit: 100 });
    assert.ok(!defaultList.items.some((item) => item.id === target.id));

    // ...but not lost. Hiding must not mean unreachable, or a suppression made
    // in error could never be found and undone.
    const filtered = await listFindings({
      limit: 100,
      triageStates: ["suppressed"],
    });
    assert.ok(filtered.items.some((item) => item.id === target.id));
  });

  test("acknowledged findings stay visible", async () => {
    // Acknowledging means "yes, this is real, it is on the list" — a reason to
    // keep looking at it, not to stop.
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));
    const target = (await listFindings({ limit: 1 })).items[0]!;
    await setTriage(target.id, "acknowledged", "Queued for the sprint.", actor);

    const list = await listFindings({ limit: 100 });
    const found = list.items.find((item) => item.id === target.id);
    assert.ok(found, "an acknowledged finding must remain in the default list");
    assert.equal(found.triageState, "acknowledged");
  });
});

// ---------------------------------------------------------------------------
// Triage writes
// ---------------------------------------------------------------------------

describe("setTriage", () => {
  test("requires a justification for anything but untriaged", async () => {
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));
    const target = (await listFindings({ limit: 1 })).items[0]!;

    for (const state of ["acknowledged", "suppressed", "false_positive"] as const) {
      await assert.rejects(
        () => setTriage(target.id, state, null, actor),
        TriageValidationError,
      );
      await assert.rejects(
        () => setTriage(target.id, state, "   ", actor),
        TriageValidationError,
      );
    }

    // Nothing was written by any of the rejected attempts.
    assert.equal(await getTriage(target.id), null);
    assert.equal((await triageHistory(target.id)).length, 0);
  });

  test("rejects an unknown finding with a named error", async () => {
    // Checked explicitly rather than left to the foreign key, so the API can
    // answer 404 rather than 500.
    await assert.rejects(
      () => setTriage("no-such-finding", "acknowledged", "x", actor),
      UnknownFindingError,
    );
  });

  test("records every transition, including the previous state", async () => {
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));
    const target = (await listFindings({ limit: 1 })).items[0]!;

    await setTriage(target.id, "acknowledged", "Seen it.", actor);
    await setTriage(target.id, "suppressed", "Accepted after review.", actor);
    await setTriage(target.id, "untriaged", null, actor);

    const history = await triageHistory(target.id);
    assert.equal(history.length, 3);

    // Newest first.
    assert.deepEqual(
      history.map((event) => [event.previousState, event.newState]),
      [
        ["suppressed", "untriaged"],
        ["acknowledged", "suppressed"],
        [null, "acknowledged"],
      ],
    );
    // Returning to untriaged clears the note, as the CHECK constraint requires.
    assert.equal((await getTriage(target.id))?.note, null);
  });

  test("keeps the audit trail after the actor's account is deleted", async () => {
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));
    const target = (await listFindings({ limit: 1 })).items[0]!;
    await setTriage(target.id, "suppressed", "Accepted.", actor);

    await deleteUser(actor.id);

    // An audit trail that can be erased by deleting a user account is not an
    // audit trail. The foreign key nulls out, the email does not.
    const history = await triageHistory(target.id);
    assert.equal(history.length, 1);
    assert.equal(history[0]!.actorEmail, "dash-test@example.invalid");
    assert.equal(history[0]!.note, "Accepted.");

    // And the triage row survives too, with its actor reference nulled.
    const triage = await getTriage(target.id);
    assert.equal(triage?.state, "suppressed");
    assert.equal(triage?.updatedBy, null);
  });

  test("counts open findings by triage state", async () => {
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));
    const all = await listFindings({ limit: 100 });

    await setTriage(all.items[0]!.id, "suppressed", "Accepted.", actor);
    await setTriage(all.items[1]!.id, "acknowledged", "Queued.", actor);

    const counts = await triageCounts();
    assert.equal(counts.suppressed, 1);
    assert.equal(counts.acknowledged, 1);
    assert.equal(counts.untriaged, all.total - 2);
  });
});

// ---------------------------------------------------------------------------
// Lists and detail
// ---------------------------------------------------------------------------

describe("listFindings", () => {
  test("orders most severe first, then longest-standing", async () => {
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));
    const items = (await listFindings({ limit: 100 })).items;

    const rank = { critical: 0, high: 1, medium: 2, low: 3 } as const;
    for (let i = 1; i < items.length; i += 1) {
      const previous = rank[items[i - 1]!.severity as keyof typeof rank];
      const current = rank[items[i]!.severity as keyof typeof rank];
      assert.ok(
        previous <= current,
        `severity order broken at index ${i}: ${items[i - 1]!.severity} before ${items[i]!.severity}`,
      );
    }
  });

  test("filters by severity, and the total matches the filter", async () => {
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));

    const critical = await listFindings({ severities: ["critical"], limit: 100 });
    assert.ok(critical.total > 0);
    assert.equal(critical.items.length, critical.total);
    assert.ok(critical.items.every((item) => item.severity === "critical"));
  });

  test("paginates with a total that counts every match, not just the page", async () => {
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));

    const page = await listFindings({ limit: 2, offset: 0 });
    // The count query and the list query share one filter definition, so a
    // total that only counted the page would mean they had drifted apart —
    // which shows up as a paginator promising pages that do not exist.
    assert.equal(page.items.length, 2);
    assert.ok(page.total > 2);

    const second = await listFindings({ limit: 2, offset: 2 });
    assert.equal(second.total, page.total);
    // Different rows.
    assert.notEqual(second.items[0]!.id, page.items[0]!.id);
  });

  test("searches titles and resource identifiers", async () => {
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));

    const byName = await listFindings({ search: "test-public", limit: 100 });
    assert.ok(byName.total > 0);

    // A search string containing SQL metacharacters must be treated as text.
    // It reaches the query as a parameter, never as SQL.
    const injection = await listFindings({
      search: "'; DROP TABLE findings; --",
      limit: 100,
    });
    assert.equal(injection.total, 0);
    // The table is, reassuringly, still there.
    assert.ok((await listFindings({ limit: 1 })).total > 0);
  });
});

describe("findingDetail", () => {
  test("returns null for an unknown id", async () => {
    assert.equal(await findingDetail("no-such-finding"), null);
  });

  test("returns every occurrence, newest first", async () => {
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-02T00:00:00.000Z"));

    const target = (await listFindings({ limit: 1 })).items[0]!;
    const detail = await findingDetail(target.id);

    assert.ok(detail);
    assert.equal(detail.occurrences.length, 2);
    assert.ok(
      detail.occurrences[0]!.detectedAt >= detail.occurrences[1]!.detectedAt,
      "occurrences must be newest first",
    );
    // The remediation text travels with the finding, so it stays readable after
    // the rule that produced it has been retuned or removed.
    assert.ok(detail.remediation.length > 0);
  });
});

describe("scanHistory", () => {
  test("reports new findings per scan", async () => {
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-02T00:00:00.000Z"));

    const history = await scanHistory(10);
    assert.equal(history.length, 2);

    // Newest first: the second scan saw nothing new, the first saw everything.
    assert.equal(history[0]!.newCount, 0);
    assert.ok(history[1]!.newCount > 0);
    // Both scans reported the same findings, so the occurrence counts match.
    assert.equal(history[0]!.findingCount, history[1]!.findingCount);
  });

  test("surfaces collection errors", async () => {
    // A scan that could not see the whole environment must be visibly marked,
    // because a lower finding count from such a scan is not evidence of a fix.
    await scanAndSave(
      inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z", [
        {
          resourceType: "s3_bucket",
          // null because the failure was the top-level list call rather than
          // one specific bucket — the case where the scan does not even know
          // what it missed.
          resourceName: null,
          operation: "ListBuckets",
          message: "connection refused",
        },
      ]),
    );

    assert.equal((await scanHistory(1))[0]!.collectionErrors, 1);
  });
});
