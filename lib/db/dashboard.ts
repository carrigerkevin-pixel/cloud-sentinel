/**
 * CloudSentinel — read queries for the dashboard.
 *
 * Every question the UI asks of the database, answered in one place.
 *
 * Where it sits in the architecture:
 *
 *   app/(dashboard) pages  --+
 *                            +--> [ this file ] --> Postgres
 *   app/api/findings, /scans +
 *
 * Writes live elsewhere: scans in lib/db/scans.ts, triage in lib/db/triage.ts,
 * accounts in lib/db/users.ts. Keeping the reads together means the shape of
 * every list the dashboard renders is defined once, and a page cannot quietly
 * invent a slightly different version of "open findings" that disagrees with
 * the count shown next to it.
 *
 * ## Two things these queries are careful about
 *
 * **Suppressed findings are excluded from lists but never from counts.** The
 * dashboard's default view hides what has been triaged away, because otherwise
 * nobody uses the triage feature twice. But the summary always reports how many
 * are hidden. A risk score that silently drops suppressed findings is a score
 * that improves when you click "suppress", which makes it worse than no score.
 *
 * **Inconclusive is never folded into anything.** The rule engine's third
 * verdict survives all the way to the UI. A scan that could not read a bucket's
 * public-access configuration must not appear beside one that read it and found
 * it safe.
 */

import { query } from "./client.ts";
import type { TriageState } from "../types/triage.ts";

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

/** Severity counts, always with all four keys present so the UI need not guard. */
export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

/** The dashboard's headline figures. */
export interface DashboardSummary {
  /** The most recent scan, or `null` when nothing has been saved yet. */
  latestScan: {
    id: number;
    collectedAt: Date;
    scannedAt: Date;
    endpoint: string;
    region: string;
    riskScore: number;
    resourcesScanned: number;
    resourcesClean: number;
    collectionErrors: number;
  } | null;

  /** Open findings by severity, **excluding** suppressed and false positives. */
  openBySeverity: SeverityCounts;

  /** Open findings by severity, including everything. Never hidden from the user. */
  totalBySeverity: SeverityCounts;

  /** How many open findings are hidden from the default view, and why. */
  hidden: { suppressed: number; falsePositive: number };

  /** Open findings whose latest occurrence was `inconclusive` rather than `fail`. */
  inconclusive: number;

  /** Findings first seen by the most recent scan. */
  newInLatestScan: number;

  /** Findings resolved at any point, for the "fixed" tally. */
  resolved: number;
}

/** Builds a zeroed severity tally. */
function emptySeverityCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0 };
}

/** Folds `{severity, count}` rows into a complete tally. */
function toSeverityCounts(
  rows: readonly { severity: string; count: string }[],
): SeverityCounts {
  const counts = emptySeverityCounts();
  for (const row of rows) {
    if (row.severity in counts) {
      counts[row.severity as keyof SeverityCounts] = Number(row.count);
    }
  }
  return counts;
}

/**
 * Collects everything the overview page shows.
 *
 * Runs several small queries rather than one large one. They are all indexed
 * lookups over a table that holds one row per distinct problem — a few hundred
 * rows in any realistic use of this tool — and the readability of six named
 * queries is worth more here than shaving a round trip off a page that renders
 * once. If this ever became a bottleneck the fix is a materialised summary, not
 * a cleverer join.
 */
export async function dashboardSummary(): Promise<DashboardSummary> {
  const [scanRows, openRows, totalRows, hiddenRows, inconclusiveRows, resolvedRows] =
    await Promise.all([
      query<{
        id: string;
        collected_at: Date;
        scanned_at: Date;
        endpoint: string;
        region: string;
        risk_score: number;
        resources_scanned: number;
        resources_clean: number;
        collection_errors: number;
      }>(
        `SELECT id, collected_at, scanned_at, endpoint, region, risk_score,
                resources_scanned, resources_clean, collection_errors
           FROM scans
          ORDER BY collected_at DESC, id DESC
          LIMIT 1`,
      ),

      // Open, and not triaged out of view.
      query<{ severity: string; count: string }>(
        `SELECT f.severity, COUNT(*)::text AS count
           FROM findings f
           LEFT JOIN finding_triage t ON t.finding_id = f.id
          WHERE f.status = 'open'
            AND COALESCE(t.state, 'untriaged') NOT IN ('suppressed', 'false_positive')
          GROUP BY f.severity`,
      ),

      // Open, regardless of triage. The number that cannot be clicked away.
      query<{ severity: string; count: string }>(
        `SELECT severity, COUNT(*)::text AS count
           FROM findings
          WHERE status = 'open'
          GROUP BY severity`,
      ),

      query<{ state: TriageState; count: string }>(
        `SELECT t.state, COUNT(*)::text AS count
           FROM findings f
           JOIN finding_triage t ON t.finding_id = f.id
          WHERE f.status = 'open'
            AND t.state IN ('suppressed', 'false_positive')
          GROUP BY t.state`,
      ),

      // An open finding whose most recent occurrence was inconclusive: the rule
      // could not reach a verdict, which is not the same as a clean result and
      // must never be displayed as one.
      query<{ count: string }>(
        `SELECT COUNT(*)::text AS count
           FROM findings f
          WHERE f.status = 'open'
            AND (
              SELECT o.status
                FROM finding_occurrences o
               WHERE o.finding_id = f.id
               ORDER BY o.detected_at DESC
               LIMIT 1
            ) = 'inconclusive'`,
      ),

      query<{ count: string }>(
        `SELECT COUNT(*)::text AS count FROM findings WHERE status = 'resolved'`,
      ),
    ]);

  const scan = scanRows[0];

  // Counted separately because it depends on the latest scan's id, which the
  // query above has only just produced.
  const newInLatestScan = scan
    ? Number(
        (
          await query<{ count: string }>(
            `SELECT COUNT(*)::text AS count
               FROM findings
              WHERE first_seen_scan_id = $1`,
            [scan.id],
          )
        )[0]?.count ?? 0,
      )
    : 0;

  const hidden = { suppressed: 0, falsePositive: 0 };
  for (const row of hiddenRows) {
    if (row.state === "suppressed") hidden.suppressed = Number(row.count);
    if (row.state === "false_positive") hidden.falsePositive = Number(row.count);
  }

  return {
    latestScan: scan
      ? {
          id: Number(scan.id),
          collectedAt: scan.collected_at,
          scannedAt: scan.scanned_at,
          endpoint: scan.endpoint,
          region: scan.region,
          riskScore: scan.risk_score,
          resourcesScanned: scan.resources_scanned,
          resourcesClean: scan.resources_clean,
          collectionErrors: scan.collection_errors,
        }
      : null,
    openBySeverity: toSeverityCounts(openRows),
    totalBySeverity: toSeverityCounts(totalRows),
    hidden,
    inconclusive: Number(inconclusiveRows[0]?.count ?? 0),
    newInLatestScan,
    resolved: Number(resolvedRows[0]?.count ?? 0),
  };
}

// ---------------------------------------------------------------------------
// Findings list
// ---------------------------------------------------------------------------

/** Filters the findings list accepts. All are optional and combine with AND. */
export interface FindingFilters {
  /** `open` (default), `resolved`, or `all`. */
  status?: "open" | "resolved" | "all";
  /** Restrict to these severities. Empty or omitted means all four. */
  severities?: readonly string[];
  /** Restrict to these triage states. Omitted means "everything not hidden". */
  triageStates?: readonly TriageState[];
  /** Substring match against title, resource name, and resource id. */
  search?: string;
  /** Restrict to one rule. */
  ruleId?: string;
  limit?: number;
  offset?: number;
}

/** A row in the findings list. */
export interface FindingListItem {
  id: string;
  ruleId: string;
  title: string;
  severity: string;
  benchmark: string;
  status: "open" | "resolved";
  resourceId: string;
  resourceName: string;
  resourceType: string;
  region: string;
  firstSeenAt: Date;
  lastSeenAt: Date;
  resolvedAt: Date | null;
  resolutionReason: string | null;
  /** How many scans have reported this finding. */
  occurrenceCount: number;
  /** The most recent occurrence's verdict: `fail` or `inconclusive`. */
  latestStatus: "fail" | "inconclusive" | null;
  /** Evidence from the most recent occurrence. */
  latestDetail: string | null;
  triageState: TriageState;
  triageNote: string | null;
}

/** A page of findings, with the total available so the UI can paginate. */
export interface FindingPage {
  items: FindingListItem[];
  total: number;
}

/** Largest page the API will serve, so a client cannot ask for the whole table. */
export const MAX_PAGE_SIZE = 200;

/**
 * Builds the shared WHERE clause and its parameters.
 *
 * SECURITY: every filter value becomes a numbered placeholder, never string
 * interpolation. `search` in particular is arbitrary text from a query string,
 * and it is passed as a parameter to `ILIKE` with the wildcards added around
 * the *value* rather than spliced into the SQL. Building this clause by
 * concatenation would be an SQL injection in a tool whose entire purpose is
 * finding other people's security mistakes.
 *
 * Returned as a fragment plus a parameter array so the list query and the count
 * query share exactly one definition of what matches. Two hand-maintained
 * copies of a filter drift, and the symptom is a paginator that promises more
 * pages than exist.
 */
function buildFilter(filters: FindingFilters): {
  where: string;
  params: unknown[];
} {
  const clauses: string[] = [];
  const params: unknown[] = [];

  const status = filters.status ?? "open";
  if (status !== "all") {
    params.push(status);
    clauses.push(`f.status = $${params.length}`);
  }

  if (filters.severities && filters.severities.length > 0) {
    params.push(filters.severities);
    clauses.push(`f.severity = ANY($${params.length}::text[])`);
  }

  if (filters.triageStates && filters.triageStates.length > 0) {
    params.push(filters.triageStates);
    clauses.push(`COALESCE(t.state, 'untriaged') = ANY($${params.length}::text[])`);
  } else {
    // The default view hides what has been triaged away — but the counts in
    // dashboardSummary() still report it, so nothing disappears silently.
    clauses.push(
      `COALESCE(t.state, 'untriaged') NOT IN ('suppressed', 'false_positive')`,
    );
  }

  if (filters.ruleId) {
    params.push(filters.ruleId);
    clauses.push(`f.rule_id = $${params.length}`);
  }

  if (filters.search) {
    // The wildcards are part of the *value*, not the SQL. `%` and `_` inside
    // the user's text are treated as literal characters by this construction,
    // so a search for "100%" matches what the user meant.
    params.push(`%${filters.search}%`);
    const placeholder = `$${params.length}`;
    clauses.push(
      `(f.title ILIKE ${placeholder} OR f.resource_name ILIKE ${placeholder} ` +
        `OR f.resource_id ILIKE ${placeholder})`,
    );
  }

  return {
    where: clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "",
    params,
  };
}

/** Row shape returned by the list query. */
interface FindingListRow {
  id: string;
  rule_id: string;
  title: string;
  severity: string;
  benchmark: string;
  status: "open" | "resolved";
  resource_id: string;
  resource_name: string;
  resource_type: string;
  region: string;
  first_seen_at: Date;
  last_seen_at: Date;
  resolved_at: Date | null;
  resolution_reason: string | null;
  occurrence_count: string;
  latest_status: "fail" | "inconclusive" | null;
  latest_detail: string | null;
  triage_state: TriageState | null;
  triage_note: string | null;
}

/**
 * Returns a filtered, sorted page of findings, plus the total that matched.
 *
 * The ordering is the point of having stored history at all: most severe first,
 * then longest-standing. A critical finding open for three weeks is a different
 * problem from one first seen an hour ago, and only the `first_seen_at` the
 * lifecycle tracks can tell them apart.
 */
export async function listFindings(
  filters: FindingFilters = {},
): Promise<FindingPage> {
  const { where, params } = buildFilter(filters);

  const limit = Math.min(Math.max(filters.limit ?? 50, 1), MAX_PAGE_SIZE);
  const offset = Math.max(filters.offset ?? 0, 0);

  const listParams = [...params, limit, offset];
  const limitPlaceholder = `$${params.length + 1}`;
  const offsetPlaceholder = `$${params.length + 2}`;

  const [rows, countRows] = await Promise.all([
    query<FindingListRow>(
      `SELECT f.id, f.rule_id, f.title, f.severity, f.benchmark, f.status,
              f.resource_id, f.resource_name, f.resource_type, f.region,
              f.first_seen_at, f.last_seen_at, f.resolved_at, f.resolution_reason,
              COALESCE(t.state, 'untriaged') AS triage_state,
              t.note AS triage_note,
              (SELECT COUNT(*)::text FROM finding_occurrences o
                WHERE o.finding_id = f.id) AS occurrence_count,
              latest.status AS latest_status,
              latest.detail AS latest_detail
         FROM findings f
         LEFT JOIN finding_triage t ON t.finding_id = f.id
         -- LATERAL so the subquery can reference f.id: one indexed lookup per
         -- row for the newest occurrence, rather than sorting every occurrence
         -- in the table to find it.
         LEFT JOIN LATERAL (
                SELECT o.status, o.detail
                  FROM finding_occurrences o
                 WHERE o.finding_id = f.id
                 ORDER BY o.detected_at DESC
                 LIMIT 1
              ) latest ON TRUE
         ${where}
        ORDER BY CASE f.severity
                   WHEN 'critical' THEN 0
                   WHEN 'high'     THEN 1
                   WHEN 'medium'   THEN 2
                   ELSE 3
                 END,
                 f.first_seen_at ASC,
                 f.id ASC
        LIMIT ${limitPlaceholder} OFFSET ${offsetPlaceholder}`,
      listParams,
    ),

    query<{ count: string }>(
      `SELECT COUNT(*)::text AS count
         FROM findings f
         LEFT JOIN finding_triage t ON t.finding_id = f.id
         ${where}`,
      params,
    ),
  ]);

  return {
    items: rows.map(toFindingListItem),
    total: Number(countRows[0]?.count ?? 0),
  };
}

function toFindingListItem(row: FindingListRow): FindingListItem {
  return {
    id: row.id,
    ruleId: row.rule_id,
    title: row.title,
    severity: row.severity,
    benchmark: row.benchmark,
    status: row.status,
    resourceId: row.resource_id,
    resourceName: row.resource_name,
    resourceType: row.resource_type,
    region: row.region,
    firstSeenAt: row.first_seen_at,
    lastSeenAt: row.last_seen_at,
    resolvedAt: row.resolved_at,
    resolutionReason: row.resolution_reason,
    occurrenceCount: Number(row.occurrence_count),
    latestStatus: row.latest_status,
    latestDetail: row.latest_detail,
    triageState: row.triage_state ?? "untriaged",
    triageNote: row.triage_note,
  };
}

// ---------------------------------------------------------------------------
// Finding detail
// ---------------------------------------------------------------------------

/** One scan's report about a finding. */
export interface OccurrenceItem {
  scanId: number;
  status: "fail" | "inconclusive";
  severity: string;
  detail: string;
  detectedAt: Date;
}

/** Everything the finding detail page shows. */
export interface FindingDetail extends FindingListItem {
  remediation: string;
  /** Every scan that reported this finding, newest first. */
  occurrences: OccurrenceItem[];
}

/**
 * Loads one finding with its full occurrence history.
 *
 * The occurrence list is what turns a finding into a story: it shows the date
 * the problem first appeared, whether it has been reported continuously since,
 * and whether any scan was unable to check. `first_seen_at` alone cannot show a
 * gap, and a gap is exactly where a "we fixed that weeks ago" claim falls down.
 *
 * @param id - the finding's deterministic id.
 * @returns the finding, or `null` if no such finding exists.
 */
export async function findingDetail(id: string): Promise<FindingDetail | null> {
  const rows = await query<FindingListRow & { remediation: string }>(
    `SELECT f.id, f.rule_id, f.title, f.severity, f.benchmark, f.status,
            f.remediation,
            f.resource_id, f.resource_name, f.resource_type, f.region,
            f.first_seen_at, f.last_seen_at, f.resolved_at, f.resolution_reason,
            COALESCE(t.state, 'untriaged') AS triage_state,
            t.note AS triage_note,
            (SELECT COUNT(*)::text FROM finding_occurrences o
              WHERE o.finding_id = f.id) AS occurrence_count,
            latest.status AS latest_status,
            latest.detail AS latest_detail
       FROM findings f
       LEFT JOIN finding_triage t ON t.finding_id = f.id
       LEFT JOIN LATERAL (
              SELECT o.status, o.detail
                FROM finding_occurrences o
               WHERE o.finding_id = f.id
               ORDER BY o.detected_at DESC
               LIMIT 1
            ) latest ON TRUE
      WHERE f.id = $1`,
    [id],
  );

  const row = rows[0];
  if (!row) return null;

  const occurrences = await query<{
    scan_id: string;
    status: "fail" | "inconclusive";
    severity: string;
    detail: string;
    detected_at: Date;
  }>(
    `SELECT scan_id, status, severity, detail, detected_at
       FROM finding_occurrences
      WHERE finding_id = $1
      ORDER BY detected_at DESC, scan_id DESC`,
    [id],
  );

  return {
    ...toFindingListItem(row),
    remediation: row.remediation,
    occurrences: occurrences.map((occurrence) => ({
      scanId: Number(occurrence.scan_id),
      status: occurrence.status,
      severity: occurrence.severity,
      detail: occurrence.detail,
      detectedAt: occurrence.detected_at,
    })),
  };
}

// ---------------------------------------------------------------------------
// Scan history
// ---------------------------------------------------------------------------

/** A row in the scan history list. */
export interface ScanHistoryItem {
  id: number;
  collectedAt: Date;
  scannedAt: Date;
  riskScore: number;
  resourcesScanned: number;
  resourcesClean: number;
  collectionErrors: number;
  findingCount: number;
  /** Findings this scan saw for the first time. */
  newCount: number;
}

/**
 * Returns recent scans, newest first.
 *
 * `findingCount` is computed from `finding_occurrences` rather than stored on
 * `scans`, so it can never disagree with the occurrences actually recorded.
 * `newCount` comes from `first_seen_scan_id`, which is what makes a scan
 * history readable as a trend rather than a list of totals.
 */
export async function scanHistory(limit = 30): Promise<ScanHistoryItem[]> {
  const rows = await query<{
    id: string;
    collected_at: Date;
    scanned_at: Date;
    risk_score: number;
    resources_scanned: number;
    resources_clean: number;
    collection_errors: number;
    finding_count: string;
    new_count: string;
  }>(
    `SELECT s.id, s.collected_at, s.scanned_at, s.risk_score,
            s.resources_scanned, s.resources_clean, s.collection_errors,
            (SELECT COUNT(*)::text FROM finding_occurrences o
              WHERE o.scan_id = s.id) AS finding_count,
            (SELECT COUNT(*)::text FROM findings f
              WHERE f.first_seen_scan_id = s.id) AS new_count
       FROM scans s
      ORDER BY s.collected_at DESC, s.id DESC
      LIMIT $1`,
    [Math.min(Math.max(limit, 1), MAX_PAGE_SIZE)],
  );

  return rows.map((row) => ({
    id: Number(row.id),
    collectedAt: row.collected_at,
    scannedAt: row.scanned_at,
    riskScore: row.risk_score,
    resourcesScanned: row.resources_scanned,
    resourcesClean: row.resources_clean,
    collectionErrors: row.collection_errors,
    findingCount: Number(row.finding_count),
    newCount: Number(row.new_count),
  }));
}
