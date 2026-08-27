/**
 * CloudSentinel — GET /api/auth/session
 *
 * Reports who the current request is authenticated as.
 *
 * Where it sits in the architecture:
 *
 *   client-side code --> [ this route ] --> lib/auth/session.ts currentUser()
 *
 * Response: 200 `{ "user": { "id", "email", "role" } }`, or 401 when there is
 * no valid session.
 *
 * The dashboard pages are server components and read `currentUser()` directly,
 * so they do not need this. It exists for the client side: after a login
 * redirect, or to re-check a session that may have been revoked while a tab sat
 * open, without having to attempt a real action to find out.
 *
 * A full check runs on every call — signature, expiry, and a database lookup
 * confirming the account still exists, the session was not revoked, and the
 * role has not changed. This route is therefore an honest answer to "am I still
 * signed in, and as what", rather than a reflection of what the cookie claims.
 */

import { requireUser } from "../../../../lib/api/guards.ts";
import { json } from "../../../../lib/api/http.ts";

export async function GET(): Promise<Response> {
  const guard = await requireUser();
  if (!guard.ok) return guard.response;

  // Only identity, never the token or anything derived from it. The role is
  // included because the UI hides admin-only controls with it — a convenience,
  // not the enforcement: every state-changing route re-checks the role server
  // side, because a hidden button is not an access control.
  return json({
    user: {
      id: guard.user.id,
      email: guard.user.email,
      role: guard.user.role,
    },
  });
}
