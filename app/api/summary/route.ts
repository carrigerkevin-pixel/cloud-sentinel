/**
 * CloudSentinel — GET /api/summary
 *
 * The overview page's headline figures: latest scan, risk score, severity
 * counts, and how much is currently hidden by triage.
 *
 * Where it sits in the architecture:
 *
 *   overview page --> [ this route ] --> lib/db/dashboard.ts dashboardSummary()
 *
 * Response: the {@link DashboardSummary} shape, verbatim.
 *
 * The response reports severity counts twice — `openBySeverity` excludes what
 * has been suppressed, `totalBySeverity` does not — along with a `hidden`
 * breakdown. That redundancy is deliberate and is the reason this endpoint
 * exists rather than the page counting rows from `/api/findings`: a summary
 * that only ever showed the filtered number would let the headline figure be
 * improved by suppressing findings, which is precisely the behaviour a posture
 * tool must not reward.
 */

import { json, requireUser } from "../../../lib/api/http.ts";
import { dashboardSummary } from "../../../lib/db/dashboard.ts";

export async function GET(): Promise<Response> {
  const guard = await requireUser();
  if (!guard.ok) return guard.response;

  return json(await dashboardSummary());
}
