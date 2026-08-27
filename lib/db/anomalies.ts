/**
 * CloudSentinel — anomaly persistence and queries.
 *
 * Writes a detection run to Postgres and reads it back for the dashboard.
 *
 * Where it sits in the architecture: the database end of the ML layer, the
 * counterpart of lib/db/scans.ts for behavioural data rather than
 * configuration.
 *
 *   ml/detect.py --> lib/anomalies/ingest.ts --> [ this file ] --> app/(app)/anomalies
 *
 * The one structural difference from lib/db/scans.ts is worth understanding,
 * because it looks like an omission and is a decision.
 *
 * `saveScan` does a great deal of work reconciling a new scan against previous
 * ones: it decides whether each finding is new, continuing, reopened or
 * resolved, and it protects `first_seen_at` so a finding's history survives.
 * All of that exists because a *finding is a condition that persists* — a
 * bucket stays public until somebody fixes it, and the interesting question is
 * how long it has been that way.
 *
 * There is no equivalent here, and there should not be. An anomaly is an
 * observation about one specific past hour. It cannot be fixed, cannot recur —
 * a later strange hour is a *different* hour — and has no meaningful status. So
 * this module simply inserts what a run saw. The full reasoning is in
 * db/migrations/0003_anomalies.sql.
 *
 * SECURITY: every query below is parameterised, with no string interpolation of
 * values anywhere. The report has already been validated by
 * lib/anomalies/ingest.ts, but validation is a check and parameterisation is a
 * guarantee — the two are not alternatives, and this layer does not rely on the
 * caller having validated anything.
 */

import type { PoolClient } from "pg";

import type {
  Anomaly,
  AnomalyEvidence,
  AnomalyModel,
  AnomalyReport,
} from "../types/anomaly.ts";
import { query, withTransaction } from "./client.ts";

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/** What {@link saveAnomalyReport} returns. */
export interface SavedAnomalyRun {
  /** The `anomaly_runs.id` of the row just written. */
  runId: number;

  /** How many anomaly rows were inserted. */
  anomalyCount: number;
}

/**
 * Inserts the run row and returns its generated id.
 *
 * @param client - the transaction's client.
 * @param report - the validated report.
 * @returns the new run's id.
 */
async function insertRun(
  client: PoolClient,
  report: AnomalyReport,
): Promise<number> {
  const { metadata } = report;

  const result = await client.query<{ id: string }>(
    `INSERT INTO anomaly_runs (
       log_seed, log_days, event_count, window_count,
       alert_budget, primary_model, model_params
     ) VALUES ($1, $2, $3, $4, $5, $6, $7)
     RETURNING id`,
    [
      metadata.seed,
      metadata.days,
      metadata.eventCount,
      metadata.windowCount,
      metadata.alertBudget,
      metadata.primaryModel,
      JSON.stringify(metadata.modelParams),
    ],
  );

  // `pg` returns BIGINT as a string, because a 64-bit integer does not fit in a
  // JavaScript number without loss. Converting here is safe: identity columns
  // start at 1 and this project will not reach 2^53 detection runs.
  return Number(result.rows[0]!.id);
}

/**
 * Inserts one anomaly.
 *
 * One statement per row rather than a hand-built multi-row `VALUES`, matching
 * `insertResources` in lib/db/scans.ts and for the same reason: a run produces
 * a few dozen alerts, so the difference is imperceptible, and a multi-row
 * insert with fourteen columns is exactly the shape of code where an off-by-one
 * in the parameter indices silently writes a score into a timestamp column.
 *
 * `ON CONFLICT DO NOTHING` against the `(run_id, principal_arn, window_start)`
 * unique constraint guards the invariant that one run holds at most one alert
 * per principal-hour. It protects against a malformed detections file listing
 * the same window twice, not against running the command twice.
 *
 * Running `npm run ml:save` twice deliberately produces two runs, in the same
 * way that re-scanning produces a new `scans` row rather than overwriting the
 * previous one. A run is a record of an analysis that happened, and two
 * analyses of the same log at different times are two events. That also makes
 * it possible to save the same log at two different alert budgets and compare
 * them, which would be impossible if a save silently replaced its predecessor.
 */
async function insertAnomaly(
  client: PoolClient,
  runId: number,
  anomaly: Anomaly,
): Promise<boolean> {
  const result = await client.query(
    `INSERT INTO anomalies (
       run_id, principal_arn, window_start, window_end, event_count,
       flagged_by, score_isolation_forest, score_baseline,
       evidence, features, sample_actions, sample_event_ids
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
     ON CONFLICT (run_id, principal_arn, window_start) DO NOTHING`,
    [
      runId,
      anomaly.principalArn,
      anomaly.windowStart,
      anomaly.windowEnd,
      anomaly.eventCount,
      anomaly.flaggedBy,
      anomaly.scores.isolationForest,
      anomaly.scores.baseline,
      JSON.stringify(anomaly.evidence),
      JSON.stringify(anomaly.features),
      anomaly.sampleActions,
      anomaly.eventIds,
    ],
  );

  return (result.rowCount ?? 0) > 0;
}

/**
 * Saves a whole detection run.
 *
 * Everything happens in one transaction, so a failure part-way through leaves
 * no run row with a partial set of alerts behind it. A half-written run would
 * be worse than no run at all: the dashboard would show a plausible-looking
 * detection summary that silently omitted some of what the model found, and
 * nothing about it would look wrong.
 *
 * @param report - a report already validated by lib/anomalies/ingest.ts.
 * @returns the new run's id and how many anomalies were inserted.
 * @throws propagates any database error after rolling the transaction back.
 */
export async function saveAnomalyReport(
  report: AnomalyReport,
): Promise<SavedAnomalyRun> {
  return withTransaction(async (client) => {
    const runId = await insertRun(client, report);

    let anomalyCount = 0;
    for (const anomaly of report.anomalies) {
      if (await insertAnomaly(client, runId, anomaly)) {
        anomalyCount += 1;
      }
    }

    return { runId, anomalyCount };
  });
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/** A detection run, as the dashboard lists it. */
export interface AnomalyRunRow {
  id: number;
  detectedAt: Date;
  logSeed: string;
  logDays: number;
  eventCount: number;
  windowCount: number;
  alertBudget: number;
  primaryModel: AnomalyModel;
  anomalyCount: number;
}

/**
 * Lists detection runs, most recent first.
 *
 * @param limit - how many to return. Defaults to 20.
 * @returns one row per run, each with its alert count.
 */
export async function recentAnomalyRuns(limit = 20): Promise<AnomalyRunRow[]> {
  const rows = await query<{
    id: string;
    detected_at: Date;
    log_seed: string;
    log_days: number;
    event_count: number;
    window_count: number;
    alert_budget: number;
    primary_model: AnomalyModel;
    anomaly_count: string;
  }>(
    `SELECT r.id, r.detected_at, r.log_seed, r.log_days, r.event_count,
            r.window_count, r.alert_budget, r.primary_model,
            COUNT(a.id) AS anomaly_count
       FROM anomaly_runs r
       LEFT JOIN anomalies a ON a.run_id = r.id
      GROUP BY r.id
      ORDER BY r.detected_at DESC, r.id DESC
      LIMIT $1`,
    [limit],
  );

  return rows.map((row) => ({
    id: Number(row.id),
    detectedAt: row.detected_at,
    logSeed: row.log_seed,
    logDays: row.log_days,
    eventCount: row.event_count,
    windowCount: row.window_count,
    alertBudget: row.alert_budget,
    primaryModel: row.primary_model,
    anomalyCount: Number(row.anomaly_count),
  }));
}

/** One flagged window, as the dashboard renders it. */
export interface AnomalyRow {
  id: number;
  runId: number;
  principalArn: string;
  /** The last path segment of the ARN — what a reader actually recognises. */
  principalName: string;
  windowStart: Date;
  windowEnd: Date;
  eventCount: number;
  flaggedBy: AnomalyModel[];
  scoreIsolationForest: number;
  scoreBaseline: number;
  evidence: AnomalyEvidence[];
  features: Record<string, number>;
  sampleActions: string[];
  sampleEventIds: string[];
}

/**
 * Maps a database row to an {@link AnomalyRow}.
 *
 * The numeric conversions matter. `pg` returns `NUMERIC` as a *string*, on
 * purpose: `NUMERIC` is arbitrary precision and a JavaScript number is not, so
 * the driver refuses to lose precision silently. For a 0-100 percentile with
 * two decimal places that precision is irrelevant, but the strings are not —
 * `"99.95" > "100.00"` is true in string comparison, so a page that sorted
 * without converting would put the wrong alert at the top.
 */
function toAnomalyRow(row: {
  id: string;
  run_id: string;
  principal_arn: string;
  window_start: Date;
  window_end: Date;
  event_count: number;
  flagged_by: string[];
  score_isolation_forest: string;
  score_baseline: string;
  evidence: AnomalyEvidence[];
  features: Record<string, number>;
  sample_actions: string[];
  sample_event_ids: string[];
}): AnomalyRow {
  return {
    id: Number(row.id),
    runId: Number(row.run_id),
    principalArn: row.principal_arn,
    principalName: row.principal_arn.split("/").pop() ?? row.principal_arn,
    windowStart: row.window_start,
    windowEnd: row.window_end,
    eventCount: row.event_count,
    flaggedBy: row.flagged_by as AnomalyModel[],
    scoreIsolationForest: Number(row.score_isolation_forest),
    scoreBaseline: Number(row.score_baseline),
    evidence: row.evidence,
    features: row.features,
    sampleActions: row.sample_actions,
    sampleEventIds: row.sample_event_ids,
  };
}

/**
 * The most recent detection run, or `null` if none has been saved.
 *
 * Used by the dashboard to decide whether to show anomalies at all. Returning
 * `null` rather than throwing is deliberate: an empty database is the normal
 * state before `npm run ml:save` has ever run, and a page that crashed on a
 * fresh install would be a poor first impression of a security tool.
 */
export async function latestAnomalyRun(): Promise<AnomalyRunRow | null> {
  const runs = await recentAnomalyRuns(1);
  return runs[0] ?? null;
}

/**
 * Lists the anomalies in a run, most anomalous first.
 *
 * Ordered by the Isolation Forest's percentile because it is the primary model.
 * A future filter by model would change the `ORDER BY`, not this function's
 * shape — both scores are on every row precisely so that is possible.
 *
 * @param runId - the run to read.
 * @param limit - how many to return. Defaults to 100, comfortably above any
 *   realistic alert budget.
 */
export async function anomaliesForRun(
  runId: number,
  limit = 100,
): Promise<AnomalyRow[]> {
  const rows = await query<Parameters<typeof toAnomalyRow>[0]>(
    `SELECT id, run_id, principal_arn, window_start, window_end, event_count,
            flagged_by, score_isolation_forest, score_baseline,
            evidence, features, sample_actions, sample_event_ids
       FROM anomalies
      WHERE run_id = $1
      ORDER BY score_isolation_forest DESC, window_start DESC
      LIMIT $2`,
    [runId, limit],
  );

  return rows.map(toAnomalyRow);
}

/**
 * Reads one anomaly by its id.
 *
 * @param id - the anomaly's primary key.
 * @returns the row, or `null` if no such anomaly exists — which is what a
 *   stale bookmark or a hand-edited URL produces, and is a 404 rather than an
 *   error.
 */
export async function anomalyById(id: number): Promise<AnomalyRow | null> {
  const rows = await query<Parameters<typeof toAnomalyRow>[0]>(
    `SELECT id, run_id, principal_arn, window_start, window_end, event_count,
            flagged_by, score_isolation_forest, score_baseline,
            evidence, features, sample_actions, sample_event_ids
       FROM anomalies
      WHERE id = $1`,
    [id],
  );

  const row = rows[0];
  return row ? toAnomalyRow(row) : null;
}

/**
 * Counts the anomalies in a run per principal.
 *
 * This is the alert-fatigue view, and it is the most operationally useful
 * summary the dashboard can show. A run in which one principal accounts for
 * most of the alerts is a run whose reader will start skipping them — which is
 * the failure mode that turns a detector's recall into zero in practice, no
 * matter what its evaluation numbers said. Surfacing the concentration makes
 * that visible before it happens rather than after.
 *
 * @param runId - the run to summarise.
 * @returns one row per principal, busiest first.
 */
export async function anomalyCountsByPrincipal(
  runId: number,
): Promise<Array<{ principalName: string; count: number }>> {
  const rows = await query<{ principal_arn: string; count: string }>(
    `SELECT principal_arn, COUNT(*) AS count
       FROM anomalies
      WHERE run_id = $1
      GROUP BY principal_arn
      ORDER BY COUNT(*) DESC, principal_arn`,
    [runId],
  );

  return rows.map((row) => ({
    principalName: row.principal_arn.split("/").pop() ?? row.principal_arn,
    count: Number(row.count),
  }));
}
