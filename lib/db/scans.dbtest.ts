/**
 * CloudSentinel — integration tests for scan persistence.
 *
 * Run with `npm run test:db`. **Requires a running PostgreSQL server**, which
 * is why these live in `.dbtest.ts` files rather than `.test.ts`: `npm test`
 * must stay runnable with no Docker, no database, and no credentials, so the
 * two suites are deliberately kept separate rather than gated by a runtime
 * check that would silently skip and give false confidence.
 *
 * What these cover that lib/db/lifecycle.test.ts cannot: the lifecycle rules
 * are a pure function and are tested exhaustively there, but the SQL that
 * executes the resulting plan is not. These tests exercise the real statements
 * against a real Postgres — the `ON CONFLICT` clause that must never overwrite
 * `first_seen_at`, the CHECK constraint on resolution consistency, and the
 * transaction boundary.
 *
 * ## Isolation
 *
 * Every run creates a dedicated `cloudsentinel_dbtest` database, migrates it,
 * and drops it at the end. It never touches the development database, so
 * running these cannot destroy real scan history — the one thing in this
 * project that cannot be regenerated.
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
import { runMigrations } from "./migrate.ts";
import { openFindings, recentScans, saveScan } from "./scans.ts";

/** Name of the throwaway database these tests create and drop. */
const TEST_DATABASE = "cloudsentinel_dbtest";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** A bucket that trips the public-access rules. */
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

/** The same bucket, fully remediated. */
function fixedBucket(): S3BucketResource {
  const bucket = publicBucket();
  bucket.config.publicAccessBlock = {
    blockPublicAcls: true,
    ignorePublicAcls: true,
    blockPublicPolicy: true,
    restrictPublicBuckets: true,
  };
  bucket.config.versioning = "Enabled";
  bucket.config.loggingEnabled = true;
  bucket.config.loggingTargetBucket = "logs";
  return bucket;
}

/** Wraps resources in an inventory with a given collection time. */
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

/** Collects an inventory, runs the rules, and stores the result. */
async function scanAndSave(inventory: ResourceInventory) {
  return saveScan(inventory, runRules(inventory));
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

before(async () => {
  loadEnvFile();

  // Connect to the server's default database purely to create the test one —
  // CREATE DATABASE cannot run from inside the database being created.
  const admin = new Pool({
    host: process.env.POSTGRES_HOST ?? "127.0.0.1",
    port: Number(process.env.POSTGRES_PORT ?? 5432),
    user: process.env.POSTGRES_USER ?? "cloudsentinel",
    password: process.env.POSTGRES_PASSWORD,
    database: "postgres",
  });

  try {
    // Dropped first in case a previous run was interrupted before cleanup.
    await admin.query(`DROP DATABASE IF EXISTS ${TEST_DATABASE}`);
    await admin.query(`CREATE DATABASE ${TEST_DATABASE}`);
  } finally {
    await admin.end();
  }

  // Point the shared client at the test database. Set before anything calls
  // getPool(), so the pool is built against the right target.
  process.env.POSTGRES_DB = TEST_DATABASE;
  process.env.DATABASE_URL = "";

  await runMigrations();
});

beforeEach(async () => {
  // Each test starts from an empty history. `RESTART IDENTITY` resets the scan
  // id sequence so ids are predictable within a test.
  await query(
    "TRUNCATE finding_occurrences, findings, resources, scans RESTART IDENTITY CASCADE",
  );
});

after(async () => {
  await closePool();

  const admin = new Pool({
    host: process.env.POSTGRES_HOST ?? "127.0.0.1",
    port: Number(process.env.POSTGRES_PORT ?? 5432),
    user: process.env.POSTGRES_USER ?? "cloudsentinel",
    password: process.env.POSTGRES_PASSWORD,
    database: "postgres",
  });
  try {
    await admin.query(`DROP DATABASE IF EXISTS ${TEST_DATABASE}`);
  } finally {
    await admin.end();
  }
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("saveScan", () => {
  test("stores the scan, its resources, and one occurrence per finding", async () => {
    const saved = await scanAndSave(
      inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"),
    );

    assert.ok(saved.scanId > 0);
    assert.ok(saved.plan.created.length > 0);

    const [scan] = await query<{ count: string }>(
      "SELECT count(*) FROM scans",
    );
    assert.equal(scan!.count, "1");

    const [resources] = await query<{ count: string }>(
      "SELECT count(*) FROM resources",
    );
    assert.equal(resources!.count, "1");

    const [occurrences] = await query<{ count: string }>(
      "SELECT count(*) FROM finding_occurrences",
    );
    assert.equal(occurrences!.count, String(saved.plan.created.length));
  });

  test("re-scanning does not duplicate findings", async () => {
    // The deterministic-id property, verified against the real ON CONFLICT
    // clause rather than in principle.
    const first = await scanAndSave(
      inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"),
    );
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-02T00:00:00.000Z"));

    const [findings] = await query<{ count: string }>(
      "SELECT count(*) FROM findings",
    );
    assert.equal(findings!.count, String(first.plan.created.length));

    // Two scans, so two occurrences of each finding.
    const [occurrences] = await query<{ count: string }>(
      "SELECT count(*) FROM finding_occurrences",
    );
    assert.equal(occurrences!.count, String(first.plan.created.length * 2));
  });

  test("never moves first_seen_at, but does advance last_seen_at", async () => {
    // The single most important storage guarantee in the phase. If first_seen_at
    // drifted, every "open for three weeks" claim would silently become
    // "open since today" and the history would be worthless.
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-09T00:00:00.000Z"));

    const rows = await query<{ first_seen_at: Date; last_seen_at: Date }>(
      "SELECT first_seen_at, last_seen_at FROM findings LIMIT 1",
    );
    assert.equal(
      rows[0]!.first_seen_at.toISOString(),
      "2026-08-01T00:00:00.000Z",
    );
    assert.equal(
      rows[0]!.last_seen_at.toISOString(),
      "2026-08-09T00:00:00.000Z",
    );
  });

  test("resolves findings when the resource is remediated", async () => {
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));
    const second = await scanAndSave(
      inventoryOf([fixedBucket()], "2026-08-02T00:00:00.000Z"),
    );

    assert.ok(second.plan.resolved.length > 0);
    const rows = await query<{ status: string; resolution_reason: string }>(
      "SELECT status, resolution_reason FROM findings WHERE status = 'resolved'",
    );
    assert.ok(rows.length > 0);
    for (const row of rows) {
      assert.equal(row.resolution_reason, "fixed");
    }
  });

  test("records resolved_at as the collection time, not the write time", async () => {
    // Saving a week-old inventory must not claim the fix happened today.
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));
    await scanAndSave(inventoryOf([fixedBucket()], "2026-08-02T00:00:00.000Z"));

    const rows = await query<{ resolved_at: Date }>(
      "SELECT resolved_at FROM findings WHERE status = 'resolved' LIMIT 1",
    );
    assert.equal(rows[0]!.resolved_at.toISOString(), "2026-08-02T00:00:00.000Z");
  });

  test("marks a finding resource_removed when the resource disappears", async () => {
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));
    // An empty inventory with no errors: the environment really is empty.
    await scanAndSave(inventoryOf([], "2026-08-02T00:00:00.000Z"));

    const rows = await query<{ resolution_reason: string }>(
      "SELECT DISTINCT resolution_reason FROM findings WHERE status = 'resolved'",
    );
    assert.deepEqual(
      rows.map((row) => row.resolution_reason),
      ["resource_removed"],
    );
  });

  test("reopens a resolved finding and keeps its original first_seen_at", async () => {
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));
    await scanAndSave(inventoryOf([fixedBucket()], "2026-08-02T00:00:00.000Z"));
    const third = await scanAndSave(
      inventoryOf([publicBucket()], "2026-08-03T00:00:00.000Z"),
    );

    assert.ok(third.plan.reopened.length > 0);

    const rows = await query<{
      status: string;
      resolved_at: Date | null;
      resolution_reason: string | null;
      first_seen_at: Date;
    }>("SELECT status, resolved_at, resolution_reason, first_seen_at FROM findings");

    for (const row of rows) {
      assert.equal(row.status, "open");
      // The CHECK constraint requires an open row to carry neither field, so
      // this also proves the UPDATE cleared them rather than the write failing.
      assert.equal(row.resolved_at, null);
      assert.equal(row.resolution_reason, null);
      assert.equal(row.first_seen_at.toISOString(), "2026-08-01T00:00:00.000Z");
    }
  });

  test("resolves nothing when the scan had collection errors", async () => {
    // The guard that prevents a failed scan from being reported as a clean
    // environment. Verified end to end, not just in the pure function.
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));

    const partial = await scanAndSave(
      inventoryOf([], "2026-08-02T00:00:00.000Z", [
        {
          resourceType: "s3_bucket",
          resourceName: null,
          operation: "ListBuckets",
          message: "simulated failure",
        },
      ]),
    );

    assert.deepEqual(partial.plan.resolved, []);
    assert.ok(partial.plan.unverified.length > 0);

    const [open] = await query<{ count: string }>(
      "SELECT count(*) FROM findings WHERE status = 'open'",
    );
    assert.equal(open!.count, String(partial.plan.unverified.length));
  });

  test("rolls the whole scan back if any statement fails", async () => {
    // A half-written scan would leave lifecycle dates that cannot be repaired
    // by re-running anything, so atomicity is a correctness requirement rather
    // than a nicety. A finding id longer than the column allows is impossible,
    // so the failure is forced with a duplicate primary key instead.
    const inventory = inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z");
    const result = runRules(inventory);

    // Two findings sharing one id: the second occurrence insert violates the
    // primary key on finding_occurrences... which is ON CONFLICT DO NOTHING, so
    // instead force a genuine constraint failure with an invalid severity.
    const corrupted = {
      ...result,
      findings: [
        ...result.findings,
        {
          ...result.findings[0]!,
          id: "bad|finding",
          severity: "catastrophic" as never,
        },
      ],
    };

    await assert.rejects(() => saveScan(inventory, corrupted));

    // Nothing at all should have landed.
    const [scans] = await query<{ count: string }>("SELECT count(*) FROM scans");
    assert.equal(scans!.count, "0");
    const [findings] = await query<{ count: string }>(
      "SELECT count(*) FROM findings",
    );
    assert.equal(findings!.count, "0");
  });
});

// ---------------------------------------------------------------------------
// Reading history
// ---------------------------------------------------------------------------

describe("history queries", () => {
  test("recentScans returns newest first with finding counts", async () => {
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-05T00:00:00.000Z"));

    const scans = await recentScans();
    assert.equal(scans.length, 2);
    assert.equal(scans[0]!.collected_at.toISOString(), "2026-08-05T00:00:00.000Z");
    assert.ok(scans[0]!.finding_count > 0);
  });

  test("openFindings excludes resolved ones and counts occurrences", async () => {
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-02T00:00:00.000Z"));

    const open = await openFindings();
    assert.ok(open.length > 0);
    // Seen by both scans.
    assert.equal(open[0]!.occurrence_count, 2);

    await scanAndSave(inventoryOf([fixedBucket()], "2026-08-03T00:00:00.000Z"));
    const afterFix = await openFindings();
    assert.ok(afterFix.length < open.length);
  });

  test("openFindings orders critical before lower severities", async () => {
    await scanAndSave(inventoryOf([publicBucket()], "2026-08-01T00:00:00.000Z"));
    const open = await openFindings();
    const severities = open.map((row) => row.severity);
    const firstMedium = severities.indexOf("medium");
    const lastCritical = severities.lastIndexOf("critical");
    if (firstMedium !== -1 && lastCritical !== -1) {
      assert.ok(
        lastCritical < firstMedium,
        "critical findings must sort before medium ones",
      );
    }
  });
});
