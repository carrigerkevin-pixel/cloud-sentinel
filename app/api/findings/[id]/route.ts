/**
 * CloudSentinel — GET /api/findings/[id]
 *
 * One finding, with its full occurrence history and triage trail.
 *
 * Where it sits in the architecture:
 *
 *   finding detail page --> [ this route ] --> lib/db/dashboard.ts findingDetail()
 *                                          --> lib/db/triage.ts triageHistory()
 *
 * The `[id]` segment is a base64url token, not the raw finding id — see
 * lib/api/finding-id.ts for why (the real ids contain forward slashes, because
 * they embed ARNs).
 *
 * Response: `{ "finding": {...}, "triageHistory": [...] }`, or 404.
 */

import { decodeFindingId } from "../../../../lib/api/finding-id.ts";
import { requireUser } from "../../../../lib/api/guards.ts";
import { json, notFound } from "../../../../lib/api/http.ts";
import { findingDetail } from "../../../../lib/db/dashboard.ts";
import { triageHistory } from "../../../../lib/db/triage.ts";

export async function GET(
  _request: Request,
  // Route params are a promise in Next 16 — awaited below.
  context: { params: Promise<{ id: string }> },
): Promise<Response> {
  const guard = await requireUser();
  if (!guard.ok) return guard.response;

  const { id: token } = await context.params;
  const findingId = decodeFindingId(token);

  // A malformed token and a well-formed token for a finding that does not exist
  // get the same 404. Nothing in the response distinguishes them, so the URL
  // cannot be used to probe which ids are real.
  if (!findingId) return notFound("No such finding.");

  const finding = await findingDetail(findingId);
  if (!finding) return notFound("No such finding.");

  return json({
    finding,
    // The audit trail is returned to any signed-in user, not only admins.
    // Viewers cannot change triage state, but they should be able to see that a
    // critical finding was suppressed, by whom, and on what grounds — an audit
    // trail only the people who can write to it may read is not much of one.
    triageHistory: await triageHistory(findingId),
  });
}
