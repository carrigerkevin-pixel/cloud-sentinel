/**
 * CloudSentinel — GET /api/findings
 *
 * The filtered, paginated findings list.
 *
 * Where it sits in the architecture:
 *
 *   findings page --> [ this route ] --> lib/db/dashboard.ts listFindings()
 *
 * Query parameters, all optional:
 *
 *   status    open | resolved | all              (default: open)
 *   severity  repeatable, or comma-separated     (default: all four)
 *   triage    repeatable, or comma-separated     (default: everything not hidden)
 *   rule      a rule id
 *   q         substring match on title, resource name, or resource id
 *   limit     1..200                             (default: 50)
 *   offset    >= 0                               (default: 0)
 *
 * Response: `{ "items": [...], "total": n, "limit": n, "offset": n }`
 *
 * ## On validating query parameters
 *
 * Every parameter below is checked against a fixed set of permitted values and
 * silently dropped if it does not match, rather than being passed through to
 * the query layer. `listFindings` already parameterises everything it receives,
 * so this is a second line of defence rather than the only one — but a filter
 * value that reaches the database at all is one more place a mistake could
 * matter, and the set of valid severities is four strings long.
 *
 * Bad values are ignored rather than rejected with a 400. A dashboard link with
 * a stale filter in it should still show findings, not an error page.
 */

import { json, requireUser } from "../../../lib/api/http.ts";
import {
  listFindings,
  MAX_PAGE_SIZE,
  type FindingFilters,
} from "../../../lib/db/dashboard.ts";
import { isTriageState, type TriageState } from "../../../lib/types/triage.ts";

/** The four severities, as the only values accepted from a query string. */
const SEVERITIES = new Set(["critical", "high", "medium", "low"]);

/**
 * Reads a repeatable parameter that also accepts a comma-separated form.
 *
 * `?severity=critical&severity=high` and `?severity=critical,high` both work,
 * because the first is what a checkbox form produces and the second is what a
 * person hand-editing a URL writes.
 */
function multiValue(params: URLSearchParams, name: string): string[] {
  return params
    .getAll(name)
    .flatMap((value) => value.split(","))
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
}

/** Parses a bounded integer, falling back when absent or nonsense. */
function intParam(
  params: URLSearchParams,
  name: string,
  fallback: number,
  min: number,
  max: number,
): number {
  const raw = params.get(name);
  if (raw === null) return fallback;

  const value = Number(raw);
  if (!Number.isInteger(value)) return fallback;

  return Math.min(Math.max(value, min), max);
}

export async function GET(request: Request): Promise<Response> {
  const guard = await requireUser();
  if (!guard.ok) return guard.response;

  const params = new URL(request.url).searchParams;

  const statusParam = params.get("status");
  const status: FindingFilters["status"] =
    statusParam === "resolved" || statusParam === "all" ? statusParam : "open";

  const severities = multiValue(params, "severity").filter((value) =>
    SEVERITIES.has(value),
  );

  const triageStates = multiValue(params, "triage").filter(
    (value): value is TriageState => isTriageState(value),
  );

  const search = params.get("q")?.trim();

  const limit = intParam(params, "limit", 50, 1, MAX_PAGE_SIZE);
  const offset = intParam(params, "offset", 0, 0, Number.MAX_SAFE_INTEGER);

  const page = await listFindings({
    status,
    severities,
    triageStates,
    ruleId: params.get("rule")?.trim() || undefined,
    // A search of only whitespace is no search at all, and passing it through
    // would ILIKE every row against '% %'.
    search: search && search.length > 0 ? search : undefined,
    limit,
    offset,
  });

  return json({ ...page, limit, offset });
}
