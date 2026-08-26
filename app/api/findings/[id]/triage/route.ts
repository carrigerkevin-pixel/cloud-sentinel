/**
 * CloudSentinel — PATCH /api/findings/[id]/triage
 *
 * Records a human decision about a finding.
 *
 * Where it sits in the architecture:
 *
 *   triage control --> [ this route ] --> lib/db/triage.ts setTriage()
 *                                            |
 *                                            +--> finding_triage  (current state)
 *                                            +--> triage_events   (audit trail)
 *
 * Request:  `{ "state": "suppressed", "note": "Accepted risk because ..." }`
 * Response: `{ "triage": {...}, "history": [...] }`
 *
 * ## The only state-changing endpoint in the application
 *
 * Everything else the dashboard exposes is a read. That makes this the one
 * route where authorization, validation, and the audit trail all have to be
 * right, and it is guarded accordingly:
 *
 * - **`requireAdmin`.** A viewer can read every finding and every triage
 *   decision, but cannot make one. The check is server-side; the UI also hides
 *   the control from viewers, but a hidden button is a convenience, not an
 *   access control.
 *
 * - **A written justification.** Enforced in lib/db/triage.ts and again by a
 *   CHECK constraint in the database. Making an inconvenient critical finding
 *   disappear should cost the person doing it a sentence under their own name.
 *
 * - **PATCH, not GET.** A state change must never be reachable by anything that
 *   merely causes a browser to fetch a URL. Combined with the session cookie's
 *   `SameSite=strict`, a cross-site request here would not carry credentials
 *   anyway.
 *
 * What this route deliberately cannot do is change whether the finding is open
 * or resolved. That belongs to the scanner, and the separation is enforced by
 * lib/db/triage.ts never issuing an UPDATE against `findings`.
 */

import { decodeFindingId } from "../../../../../lib/api/finding-id.ts";
import {
  apiError,
  invalidInput,
  json,
  notFound,
  readJson,
  requireAdmin,
} from "../../../../../lib/api/http.ts";
import {
  isTriageState,
  MAX_NOTE_LENGTH,
  setTriage,
  triageHistory,
  TriageValidationError,
  UnknownFindingError,
} from "../../../../../lib/db/triage.ts";

export async function PATCH(
  request: Request,
  context: { params: Promise<{ id: string }> },
): Promise<Response> {
  const guard = await requireAdmin();
  if (!guard.ok) return guard.response;

  const { id: token } = await context.params;
  const findingId = decodeFindingId(token);
  if (!findingId) return notFound("No such finding.");

  const body = await readJson(request);
  if (body === null) return invalidInput("A JSON body is required.");

  const state = (body as Record<string, unknown>).state;
  if (!isTriageState(state)) {
    return invalidInput(
      "state must be one of: untriaged, acknowledged, suppressed, false_positive.",
    );
  }

  const rawNote = (body as Record<string, unknown>).note;
  if (rawNote !== undefined && rawNote !== null && typeof rawNote !== "string") {
    return invalidInput("note must be a string.");
  }
  // Checked here as well as in setTriage so an over-long note is a 400 rather
  // than travelling to the database first.
  if (typeof rawNote === "string" && rawNote.length > MAX_NOTE_LENGTH) {
    return invalidInput(
      `The note must be ${MAX_NOTE_LENGTH} characters or fewer.`,
    );
  }

  try {
    const triage = await setTriage(
      findingId,
      state,
      typeof rawNote === "string" ? rawNote : null,
      guard.user,
    );

    // The updated history comes back with the change, so the UI can render the
    // new audit entry without a second request — and so what it displays is
    // what was actually stored rather than what it optimistically assumed.
    return json({ triage, history: await triageHistory(findingId) });
  } catch (error) {
    if (error instanceof UnknownFindingError) {
      return notFound("No such finding.");
    }
    if (error instanceof TriageValidationError) {
      // Safe to show verbatim: every one of these tells the user something they
      // can fix, and none of them reveals anything they could not already see.
      return invalidInput(error.message);
    }

    // Anything else is a server fault. Logged in full for the operator, and
    // reported to the client as a bare 500 — a stack trace or driver message in
    // the response body is free information about the schema and the stack.
    console.error("[triage] failed to record decision", error);
    return apiError(500, "server_error", "Could not record the decision.");
  }
}
