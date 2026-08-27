/**
 * CloudSentinel — POST /api/auth/logout
 *
 * Clears the session cookie.
 *
 * Where it sits in the architecture:
 *
 *   dashboard header --> [ this route ] --> lib/auth/session.ts clearSession()
 *
 * Response: 200 `{ "ok": true }`, always.
 *
 * ## Why POST and not GET
 *
 * Logging out changes state, and a GET that changes state can be triggered by
 * anything that causes the browser to fetch a URL — an `<img src>` on another
 * site, a link preview in a chat client, a prefetching browser extension. That
 * turns "log out" into something a third party can do to a user without their
 * involvement. It is a mild attack, but it is free to prevent, and the rule it
 * follows — state changes go through POST — is one worth applying without
 * exception rather than case by case.
 *
 * Combined with the session cookie's `SameSite=strict`, a cross-site POST here
 * would not carry the cookie anyway.
 *
 * ## What this cannot do
 *
 * It cannot invalidate the token. A JWT stays valid until it expires, and the
 * server keeps no list of issued tokens to strike it from; this only asks the
 * browser to forget its copy. A token already copied elsewhere keeps working
 * until `exp`.
 *
 * That is the honest limitation of stateless sessions, and it is why
 * `revokeSessions` in lib/db/users.ts exists as a separate operation —
 * `npm run user:revoke` bumps `token_version` and kills every token for that
 * account immediately, everywhere. "Log out on this device" and "end every
 * session" are genuinely different actions, and this route is only the first.
 */

import { checkSameOrigin, json } from "../../../../lib/api/http.ts";
import { clearSession } from "../../../../lib/auth/session.ts";

export async function POST(request: Request): Promise<Response> {
  // An origin check, but no *authentication* guard. Logging out an
  // already-logged-out client is harmless, and requiring a valid session to
  // clear a cookie would leave a user holding an expired token with no way to
  // tidy up after it.
  //
  // The origin check still earns its place. Forced logout is a nuisance attack
  // rather than a breach, but it is a real one: a hostile page that can sign an
  // operator out of their monitoring dashboard on every visit is a denial of
  // service against the person watching for alerts.
  const crossSite = checkSameOrigin(request);
  if (crossSite) return crossSite;

  await clearSession();

  return json({ ok: true });
}
