/**
 * CloudSentinel — scan persistence.
 *
 * Writes a completed scan to Postgres and applies the finding-lifecycle changes
 * it implies. This is the file that turns a stateless scan into history.
 *
 * Where it sits in the architecture:
 *
 *   ScanResult + ResourceInventory
 *          |
 *          +--> lib/db/lifecycle.ts   decides what changed  (pure)
 *          +--> [ this file ]         writes it             (SQL)
 *                     |
 *                     +--> Postgres (scans, resources, findings, finding_occurrences)
 *
 * Entry point: `npm run scan -- --save`.
 *
 * Two things this file is careful about.
 *
 * **Everything happens in one transaction.** A scan touches four tables and
 * mutates lifecycle state that cannot be recomputed — once `first_seen_at` is
 * wrong, no amount of re-scanning fixes it, because the information about when
 * the problem actually appeared is gone. So either the whole scan lands or none
 * of it does.
 *
 * **Every value is passed as a query parameter, never interpolated.** Resource
 * names, ARNs, and policy text come from an AWS account CloudSentinel does not
 * control, and flow into `detail` strings. String-built SQL here would be an
 * injection vector in a security tool — the sort of thing this project exists
 * to flag in other people's infrastructure.
 */

import type { PoolClient } from "pg";

import type { Finding, ScanResult } from "../rules/types.ts";
import type { Resource, ResourceInventory } from "../types/resource.ts";
import { query, withTransaction } from "./client.ts";
import {
  planLifecycle,
  type LifecyclePlan,
  type StoredFinding,
} from "./lifecycle.ts";

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

/** What {@link saveScan} reports back, for CLI output. */
export interface SavedScan {
  /** Primary key of the new `scans` row. */
  scanId: number;
  /** The lifecycle changes that were applied. */
  plan: LifecyclePlan;
}

// ---------------------------------------------------------------------------
// Reading current state
// ---------------------------------------------------------------------------

/** Row shape returned when loading stored findings for the lifecycle decision. */
interface StoredFindingRow {
  id: string;
  rule_id: string;
  resource_id: string;
  status: "open" | "resolved";
}

/**
 * Loads every stored finding, so the lifecycle can classify this scan against
 * it.
 *
 * Both open and resolved findings are loaded: resolved ones are needed to
 * distinguish a genuinely new finding from one that has come back, and those
 * are different events worth telling apart.
 *
 * Reads through the transaction's client rather than the pool, so the snapshot
 * it sees is the same one the subsequent writes operate on. Using the pool here
 * would open a second connection outside the transaction, and a concurrent scan
 * could change the data between the read and the write.
 */
async function loadStoredFindings(
  client: PoolClient,
): Promise<StoredFinding[]> {
  const { rows } = await client.query<StoredFindingRow>(
    "SELECT id, rule_id, resource_id, status FROM findings",
  );
  return rows.map((row) => ({
    id: row.id,
    ruleId: row.rule_id,
    resourceId: row.resource_id,
    status: row.status,
  }));
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/** Inserts the `scans` row and returns its generated id. */
async function insertScan(
  client: PoolClient,
  result: ScanResult,
): Promise<number> {
  const { rows } = await client.query<{ id: string }>(
    `INSERT INTO scans (
       collected_at, scanned_at, endpoint, region,
       resources_scanned, resources_clean, risk_score, collection_errors
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     RETURNING id`,
    [
      result.collectedAt,
      result.scannedAt,
      result.endpoint,
      result.region,
      result.resourcesScanned,
      result.resourcesClean,
      result.riskScore,
      result.collectionErrors,
    ],
  );

  // Postgres returns BIGINT as a string, because a 64-bit integer does not fit
  // in a JavaScript number without loss. Converting here is safe: the value is
  // a freshly generated identity that will not approach 2^53 in this project's
  // lifetime, and keeping the id a number downstream avoids threading a string
  // through every signature.
  return Number(rows[0]!.id);
}

/**
 * Inserts the resources this scan observed.
 *
 * Written one statement per resource rather than as one multi-row insert. With
 * inventories of a few dozen resources the difference is imperceptible, and the
 * simple form keeps the parameter indices readable — a hand-built multi-row
 * `VALUES ($1,$2,...,$9),($10,...)` is exactly the kind of code where an
 * off-by-one silently writes a region into a name column.
 */
async function insertResources(
  client: PoolClient,
  scanId: number,
  resources: readonly Resource[],
): Promise<void> {
  for (const resource of resources) {
    await client.query(
      `INSERT INTO resources (
         scan_id, resource_id, resource_type, name, region, tags, config, unobserved
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        scanId,
        resource.id,
        resource.type,
        resource.name,
        resource.region,
        JSON.stringify(resource.tags),
        JSON.stringify(resource.config),
        resource.unobserved,
      ],
    );
  }
}

/**
 * Inserts a finding's lifecycle row, or updates the existing one.
 *
 * The `ON CONFLICT` clause is what makes re-scanning idempotent, and the choice
 * of which columns it updates is the whole design in miniature:
 *
 *   - `first_seen_at` and `first_seen_scan_id` are **never** overwritten. They
 *     are the reason this table exists. Letting them move would silently
 *     rewrite history every time a scan ran, and "public since August" would
 *     always read as "public since today".
 *   - `last_seen_at`, `status`, and the rule metadata are refreshed, so a
 *     reopened finding returns to `open` and a retuned severity is reflected.
 *   - `resolved_at` and `resolution_reason` are cleared, because a finding
 *     being written here means this scan reported it — it is open by
 *     definition, and the database's CHECK constraint enforces that an open row
 *     carries neither field.
 */
async function upsertFinding(
  client: PoolClient,
  scanId: number,
  finding: Finding,
): Promise<void> {
  await client.query(
    `INSERT INTO findings (
       id, rule_id, title, severity, benchmark, remediation,
       resource_id, resource_name, resource_type, region,
       status, first_seen_at, last_seen_at, first_seen_scan_id, last_seen_scan_id
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'open',$11,$11,$12,$12)
     ON CONFLICT (id) DO UPDATE SET
       title             = EXCLUDED.title,
       severity          = EXCLUDED.severity,
       benchmark         = EXCLUDED.benchmark,
       remediation       = EXCLUDED.remediation,
       resource_name     = EXCLUDED.resource_name,
       region            = EXCLUDED.region,
       status            = 'open',
       resolved_at       = NULL,
       resolution_reason = NULL,
       last_seen_at      = EXCLUDED.last_seen_at,
       last_seen_scan_id = EXCLUDED.last_seen_scan_id`,
    [
      finding.id,
      finding.ruleId,
      finding.title,
      finding.severity,
      finding.benchmark,
      finding.remediation,
      finding.resourceId,
      finding.resourceName,
      finding.resourceType,
      finding.region,
      finding.detectedAt,
      scanId,
    ],
  );
}

/** Records what this specific scan saw about this specific finding. */
async function insertOccurrence(
  client: PoolClient,
  scanId: number,
  finding: Finding,
): Promise<void> {
  await client.query(
    `INSERT INTO finding_occurrences (
       scan_id, finding_id, status, severity, detail, detected_at
     ) VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT (scan_id, finding_id) DO NOTHING`,
    [
      scanId,
      finding.id,
      finding.status,
      finding.severity,
      finding.detail,
      finding.detectedAt,
    ],
  );
}

/**
 * Marks findings resolved.
 *
 * `resolved_at` is the scan's collection time rather than `now()`, so the date
 * reflects when the environment was observed to be clean, not when the row
 * happened to be written. Saving a scan from a week-old inventory must not
 * claim the fix happened today.
 *
 * The `WHERE status = 'open'` guard makes this safe to re-run: a finding that
 * is somehow already resolved keeps its original resolution date rather than
 * having it overwritten.
 */
async function resolveFindings(
  client: PoolClient,
  plan: LifecyclePlan,
  resolvedAt: string,
): Promise<void> {
  for (const resolution of plan.resolved) {
    await client.query(
      `UPDATE findings
          SET status = 'resolved',
              resolved_at = $2,
              resolution_reason = $3
        WHERE id = $1 AND status = 'open'`,
      [resolution.id, resolvedAt, resolution.reason],
    );
  }
}

// ---------------------------------------------------------------------------
// The entry point
// ---------------------------------------------------------------------------

/**
 * Saves a scan and applies its lifecycle changes, atomically.
 *
 * @param inventory - the collected inventory the scan ran over. Needed
 *   separately from `result` because the lifecycle decision depends on which
 *   *resources* were observed, which a `ScanResult` does not carry — it knows
 *   only how many.
 * @param result - the rule engine's output for that inventory.
 * @returns the new scan's id and the lifecycle plan that was applied.
 * @throws if any statement fails, having rolled the whole scan back. The
 *   database is left exactly as it was.
 */
export async function saveScan(
  inventory: ResourceInventory,
  result: ScanResult,
): Promise<SavedScan> {
  return withTransaction(async (client) => {
    const stored = await loadStoredFindings(client);

    const plan = planLifecycle(stored, {
      findings: result.findings,
      observedResourceIds: new Set(
        inventory.resources.map((resource) => resource.id),
      ),
      // Only rules that actually evaluated something appear in `ruleSummaries`,
      // which is precisely the guarantee the lifecycle logic needs: a rule that
      // ran must not have its old findings closed by a scan where it did not.
      evaluatedRuleIds: new Set(
        result.ruleSummaries.map((summary) => summary.ruleId),
      ),
      hadCollectionErrors: result.collectionErrors > 0,
    });

    const scanId = await insertScan(client, result);
    await insertResources(client, scanId, inventory.resources);

    // Lifecycle rows first, then occurrences: `finding_occurrences` has a
    // foreign key onto `findings`, so the parent row has to exist. Every
    // finding this scan reported is written, regardless of which bucket the
    // plan put it in — the buckets describe what *changed*, not what to store.
    for (const finding of result.findings) {
      await upsertFinding(client, scanId, finding);
      await insertOccurrence(client, scanId, finding);
    }

    await resolveFindings(client, plan, result.collectedAt);

    return { scanId, plan };
  });
}

// ---------------------------------------------------------------------------
// Reading history
// ---------------------------------------------------------------------------

/** A row in the scan history list. */
export interface ScanSummaryRow {
  id: number;
  collected_at: Date;
  risk_score: number;
  resources_scanned: number;
  finding_count: number;
  collection_errors: number;
}

/**
 * Returns the most recent scans, newest first.
 *
 * Backs `npm run db:status`-style output and, later, the dashboard's scan
 * history. The finding count is computed from `finding_occurrences` rather than
 * stored on `scans`, so it can never disagree with the occurrences actually
 * recorded.
 *
 * @param limit - how many scans to return. Defaults to 10.
 */
export async function recentScans(
  limit = 10,
): Promise<ScanSummaryRow[]> {
  return query<ScanSummaryRow>(
    `SELECT s.id,
            s.collected_at,
            s.risk_score,
            s.resources_scanned,
            s.collection_errors,
            COUNT(o.finding_id)::int AS finding_count
       FROM scans s
       LEFT JOIN finding_occurrences o ON o.scan_id = s.id
      GROUP BY s.id
      ORDER BY s.collected_at DESC
      LIMIT $1`,
    [limit],
  );
}

/** A row in the open-findings list, with its lifecycle dates. */
export interface OpenFindingRow {
  id: string;
  title: string;
  severity: string;
  resource_name: string;
  resource_type: string;
  first_seen_at: Date;
  last_seen_at: Date;
  /** How many scans have reported this finding. */
  occurrence_count: number;
}

/**
 * Returns currently-open findings, most severe and longest-standing first.
 *
 * The ordering is the point of the whole phase: a critical finding that has
 * been open for three weeks is a different problem from one first seen an hour
 * ago, and only stored history can tell them apart.
 */
export async function openFindings(limit = 50): Promise<OpenFindingRow[]> {
  return query<OpenFindingRow>(
    `SELECT f.id,
            f.title,
            f.severity,
            f.resource_name,
            f.resource_type,
            f.first_seen_at,
            f.last_seen_at,
            COUNT(o.scan_id)::int AS occurrence_count
       FROM findings f
       LEFT JOIN finding_occurrences o ON o.finding_id = f.id
      WHERE f.status = 'open'
      GROUP BY f.id
      ORDER BY CASE f.severity
                 WHEN 'critical' THEN 0
                 WHEN 'high'     THEN 1
                 WHEN 'medium'   THEN 2
                 ELSE 3
               END,
               f.first_seen_at ASC
      LIMIT $1`,
    [limit],
  );
}
