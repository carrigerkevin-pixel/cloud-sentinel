/**
 * CloudSentinel — GET /api/scans
 *
 * The scan history: one entry per saved run, newest first.
 *
 * Where it sits in the architecture:
 *
 *   scan history page --> [ this route ] --> lib/db/dashboard.ts scanHistory()
 *
 * Query parameters:
 *
 *   limit   1..200   (default: 30)
 *
 * Response: `{ "scans": [...] }`
 *
 * Each entry carries `findingCount` and `newCount`. The second is what makes
 * the list readable as a trend rather than a column of totals: a scan that
 * reported fourteen findings of which zero were new is a very different event
 * from one where all fourteen were.
 */

import { json, requireUser } from "../../../lib/api/http.ts";
import { MAX_PAGE_SIZE, scanHistory } from "../../../lib/db/dashboard.ts";

export async function GET(request: Request): Promise<Response> {
  const guard = await requireUser();
  if (!guard.ok) return guard.response;

  const raw = Number(new URL(request.url).searchParams.get("limit"));
  const limit = Number.isInteger(raw)
    ? Math.min(Math.max(raw, 1), MAX_PAGE_SIZE)
    : 30;

  return json({ scans: await scanHistory(limit) });
}
