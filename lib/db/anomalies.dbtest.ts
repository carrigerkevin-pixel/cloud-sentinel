/**
 * CloudSentinel — integration tests for anomaly persistence.
 *
 * Run with `npm run test:db`. **Requires a running PostgreSQL server**, which is
 * why these live in a `.dbtest.ts` file rather than `.test.ts`: `npm test` must
 * stay runnable with no Docker, no database and no credentials, so the two
 * suites are kept separate rather than gated by a runtime check that would
 * silently skip and give false confidence.
 *
 * What these cover that lib/anomalies/ingest.test.ts cannot: that file validates
 * the *shape* of a detections document as a pure function. Nothing there
 * executes SQL, so nothing there proves the schema in
 * db/migrations/0003_anomalies.sql actually accepts what the validator lets
 * through. These tests exercise the real statements against a real Postgres —
 * the `TEXT[]` and `JSONB` columns, the CHECK constraints, the unique
 * constraint that keeps one verdict per principal-hour, and the transaction
 * boundary that stops a half-written run from ever existing.
 *
 * The distinction matters more here than for most tables, because a run written
 * with an unnoticed failure halfway through would not look broken: the
 * dashboard would show a plausible detection summary that silently omitted part
 * of what the model found.
 *
 * ## Isolation
 *
 * Every run creates a dedicated `cloudsentinel_anomtest` database, migrates it,
 * and drops it at the end. The name is deliberately different from the other
 * `.dbtest.ts` files' databases because `node --test` runs test files
 * concurrently — sharing a name would let two suites truncate each other's
 * tables mid-assertion.
 */

import assert from "node:assert/strict";
import { after, before, beforeEach, describe, test } from "node:test";

import { Pool } from "pg";

import type { Anomaly, AnomalyReport } from "../types/anomaly.ts";
import { loadEnvFile } from "../util/env.ts";
import {
  anomaliesForRun,
  anomalyById,
  anomalyCountsByPrincipal,
  latestAnomalyRun,
  recentAnomalyRuns,
  saveAnomalyReport,
} from "./anomalies.ts";
import { closePool, query } from "./client.ts";
import { runMigrations } from "./migrate.ts";

/** Name of the throwaway database these tests create and drop. */
const TEST_DATABASE = "cloudsentinel_anomtest";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Builds one anomaly, with any field overridden. */
function anomaly(overrides: Partial<Anomaly> = {}): Anomaly {
  return {
    principalArn: "arn:aws:iam::123456789012:user/alice-analyst",
    windowStart: "2026-06-16T03:00:00.000Z",
    windowEnd: "2026-06-16T04:00:00.000Z",
    eventCount: 9,
    flaggedBy: ["isolation_forest", "baseline"],
    scores: { isolationForest: 99.9, baseline: 98.5 },
    rawScores: { isolationForest: 0.187, baseline: 75 },
    evidence: [
      {
        feature: "sensitive_novelty",
        zScore: 25,
        description: "sensitive calls weighed against history",
      },
    ],
    sampleActions: ["AttachUserPolicy", "CreateAccessKey"],
    features: { sensitive_novelty: 4, event_count: 9, hour_rarity: 0.98 },
    eventIds: ["event-1", "event-2"],
    ...overrides,
  };
}

/** Builds a detections report around a set of anomalies. */
function report(anomalies: Anomaly[]): AnomalyReport {
  return {
    metadata: {
      seed: "cloudsentinel",
      days: 30,
      eventCount: 36461,
      windowCount: 1990,
      alertBudget: 20,
      primaryModel: "isolation_forest",
      modelParams: { isolationForest: { nEstimators: 200 } },
    },
    anomalies,
  };
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

  process.env.POSTGRES_DB = TEST_DATABASE;
  process.env.DATABASE_URL = "";

  await runMigrations();
});

beforeEach(async () => {
  await query("TRUNCATE anomalies, anomaly_runs RESTART IDENTITY CASCADE");
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
// Writing
// ---------------------------------------------------------------------------

describe("saveAnomalyReport", () => {
  test("stores the run and its anomalies", async () => {
    const saved = await saveAnomalyReport(report([anomaly()]));

    assert.ok(saved.runId > 0);
    assert.equal(saved.anomalyCount, 1);

    const runs = await recentAnomalyRuns();
    assert.equal(runs.length, 1);
    assert.equal(runs[0]!.logSeed, "cloudsentinel");
    assert.equal(runs[0]!.alertBudget, 20);
    assert.equal(runs[0]!.anomalyCount, 1);
  });

  test("round-trips the array and JSONB columns intact", async () => {
    // The columns most likely to break silently. `flagged_by` is TEXT[],
    // `evidence` and `features` are JSONB, and a driver-level mistake in any of
    // them shows up as an empty array or a stringified object on the dashboard
    // rather than as an error here.
    await saveAnomalyReport(report([anomaly()]));

    const [row] = await anomaliesForRun(1);
    assert.ok(row);

    assert.deepEqual(row.flaggedBy, ["isolation_forest", "baseline"]);
    assert.deepEqual(row.sampleActions, ["AttachUserPolicy", "CreateAccessKey"]);
    assert.deepEqual(row.sampleEventIds, ["event-1", "event-2"]);
    assert.equal(row.evidence.length, 1);
    assert.equal(row.evidence[0]!.feature, "sensitive_novelty");
    assert.equal(row.features.hour_rarity, 0.98);
  });

  test("returns scores as numbers, not strings", async () => {
    // `pg` returns NUMERIC as a string to avoid losing precision. For a 0-100
    // percentile that precision is irrelevant, but the string is not:
    // `"99.95" > "100.00"` is true in string comparison, so a page that sorted
    // without converting would put the wrong alert at the top.
    await saveAnomalyReport(report([anomaly()]));

    const [row] = await anomaliesForRun(1);
    assert.ok(row);

    assert.equal(typeof row.scoreIsolationForest, "number");
    assert.equal(typeof row.scoreBaseline, "number");
    assert.equal(row.scoreIsolationForest, 99.9);
  });

  test("stores an empty evidence array", async () => {
    // Meaningful rather than missing: a window isolated on a combination of
    // unremarkable features has no single feature worth naming.
    await saveAnomalyReport(report([anomaly({ evidence: [] })]));

    const [row] = await anomaliesForRun(1);
    assert.deepEqual(row!.evidence, []);
  });

  test("stores a run with no anomalies at all", async () => {
    // A clean detection run is a legitimate result, not an error.
    const saved = await saveAnomalyReport(report([]));

    assert.equal(saved.anomalyCount, 0);
    assert.equal((await recentAnomalyRuns())[0]!.anomalyCount, 0);
  });

  test("saving the same report twice produces two independent runs", async () => {
    // Deliberate, and the same behaviour as re-scanning: a run records an
    // analysis that happened. It is also what makes it possible to save one log
    // at two alert budgets and compare them.
    const first = await saveAnomalyReport(report([anomaly()]));
    const second = await saveAnomalyReport(report([anomaly()]));

    assert.notEqual(first.runId, second.runId);
    assert.equal((await recentAnomalyRuns()).length, 2);
    assert.equal((await anomaliesForRun(first.runId)).length, 1);
    assert.equal((await anomaliesForRun(second.runId)).length, 1);
  });

  test("a duplicate window within one run is stored once", async () => {
    // The unique constraint's real job: a malformed detections file listing the
    // same principal-hour twice must not produce two contradictory alerts.
    const saved = await saveAnomalyReport(report([anomaly(), anomaly()]));

    assert.equal(saved.anomalyCount, 1);
    assert.equal((await anomaliesForRun(saved.runId)).length, 1);
  });

  test("the same window in two different runs is kept separately", async () => {
    const a = await saveAnomalyReport(report([anomaly()]));
    const b = await saveAnomalyReport(report([anomaly()]));

    assert.equal((await anomaliesForRun(a.runId)).length, 1);
    assert.equal((await anomaliesForRun(b.runId)).length, 1);
  });
});

// ---------------------------------------------------------------------------
// Constraints
// ---------------------------------------------------------------------------

describe("schema constraints", () => {
  test("rejects a window that ends before it starts", async () => {
    await assert.rejects(
      saveAnomalyReport(
        report([
          anomaly({
            windowStart: "2026-06-16T04:00:00.000Z",
            windowEnd: "2026-06-16T03:00:00.000Z",
          }),
        ]),
      ),
      /anomalies_window_order/,
    );
  });

  test("rejects an out-of-range percentile", async () => {
    await assert.rejects(
      saveAnomalyReport(
        report([anomaly({ scores: { isolationForest: 150, baseline: 50 } })]),
      ),
      /score_isolation_forest/,
    );
  });

  test("rejects an anomaly flagged by nothing", async () => {
    await assert.rejects(
      saveAnomalyReport(report([anomaly({ flaggedBy: [] })])),
      /flagged_by/,
    );
  });

  test("a failed insert rolls the whole run back", async () => {
    // The transaction boundary. A run row left behind with only some of its
    // alerts would not look broken — the dashboard would render a plausible
    // summary that quietly omitted part of what the model found.
    await assert.rejects(
      saveAnomalyReport(
        report([
          // The first inserts cleanly; the second violates the event_count
          // CHECK, so the run row and the first anomaly must both disappear.
          anomaly(),
          anomaly({
            principalArn: "arn:aws:iam::123456789012:user/bob-devops",
            eventCount: -1,
          }),
        ]),
      ),
    );

    assert.deepEqual(await recentAnomalyRuns(), []);
    const rows = await query<{ count: string }>("SELECT COUNT(*) FROM anomalies");
    assert.equal(rows[0]!.count, "0");
  });
});

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

describe("queries", () => {
  test("latestAnomalyRun returns null before anything is saved", async () => {
    // A fresh install is a normal state, not an error — a dashboard that
    // crashed here would be a poor first impression of a security tool.
    assert.equal(await latestAnomalyRun(), null);
  });

  test("latestAnomalyRun returns the most recent run", async () => {
    await saveAnomalyReport(report([anomaly()]));
    const second = await saveAnomalyReport(report([anomaly(), anomaly({
      principalArn: "arn:aws:iam::123456789012:user/bob-devops",
    })]));

    const latest = await latestAnomalyRun();
    assert.equal(latest!.id, second.runId);
    assert.equal(latest!.anomalyCount, 2);
  });

  test("anomaliesForRun orders by the primary model's score", async () => {
    const saved = await saveAnomalyReport(
      report([
        anomaly({
          principalArn: "arn:aws:iam::123456789012:user/low",
          scores: { isolationForest: 90, baseline: 99 },
        }),
        anomaly({
          principalArn: "arn:aws:iam::123456789012:user/high",
          scores: { isolationForest: 99.9, baseline: 10 },
        }),
      ]),
    );

    const rows = await anomaliesForRun(saved.runId);
    assert.deepEqual(
      rows.map((row) => row.principalName),
      ["high", "low"],
    );
  });

  test("anomalyById returns null for an unknown id", async () => {
    // What a stale bookmark produces. Must be a 404, not an error.
    assert.equal(await anomalyById(999_999), null);
  });

  test("anomalyById returns the row and derives the principal name", async () => {
    await saveAnomalyReport(report([anomaly()]));
    const [listed] = await anomaliesForRun(1);

    const row = await anomalyById(listed!.id);
    assert.equal(row!.principalName, "alice-analyst");
    assert.equal(row!.eventCount, 9);
  });

  test("anomalyCountsByPrincipal ranks the noisiest principal first", async () => {
    // The alert-fatigue query. A run dominated by one principal is one whose
    // reader will start skipping it.
    const backup = "arn:aws:iam::123456789012:role/cloudsentinel-backup-service";
    const saved = await saveAnomalyReport(
      report([
        anomaly(),
        anomaly({ principalArn: backup, windowStart: "2026-06-01T02:00:00.000Z", windowEnd: "2026-06-01T03:00:00.000Z" }),
        anomaly({ principalArn: backup, windowStart: "2026-06-02T02:00:00.000Z", windowEnd: "2026-06-02T03:00:00.000Z" }),
        anomaly({ principalArn: backup, windowStart: "2026-06-03T02:00:00.000Z", windowEnd: "2026-06-03T03:00:00.000Z" }),
      ]),
    );

    const counts = await anomalyCountsByPrincipal(saved.runId);
    assert.equal(counts[0]!.principalName, "cloudsentinel-backup-service");
    assert.equal(counts[0]!.count, 3);
    assert.equal(counts[1]!.principalName, "alice-analyst");
    assert.equal(counts[1]!.count, 1);
  });
});
