/**
 * CloudSentinel — session cookies and the current-request identity.
 *
 * Bridges the crypto in lib/auth/jwt.ts to the HTTP layer: how a token is
 * carried between browser and server, and how a route handler or server
 * component asks "who is making this request".
 *
 * Where it sits in the architecture:
 *
 *   app/api/auth/login   --> issueSession()  --> Set-Cookie
 *   app/api/**           --> requireUser()   --+
 *   app/(dashboard)/**   --> currentUser()   --+--> lib/auth/jwt.ts  (signature)
 *                                              +--> lib/db/users.ts (still valid?)
 *   app/api/auth/logout  --> clearSession()
 *
 * ## Why a cookie rather than an Authorization header
 *
 * The usual advice for JWTs is to send them in an `Authorization: Bearer`
 * header, which requires storing the token somewhere JavaScript can reach —
 * in practice `localStorage`. That is the wrong trade for this application.
 *
 * A token in `localStorage` is readable by any script running on the page, so a
 * single cross-site scripting flaw — in this code, or in any dependency, now or
 * after some future upgrade — hands an attacker a working admin session that
 * they can carry off and replay from anywhere. An `httpOnly` cookie is not
 * readable by script at all, so the same XSS flaw is limited to acting through
 * the victim's browser while they are on the page. Both are bad; only one of
 * them exfiltrates.
 *
 * The trade-off is that cookies are attached automatically, which is precisely
 * what makes cross-site request forgery possible. `SameSite` is the answer to
 * that, and is set to its strictest value below.
 */

import { cookies } from "next/headers";

import { findUserById, userForClaims, type User } from "../db/users.ts";
import { signToken, TOKEN_LIFETIME_SECONDS, verifyToken } from "./jwt.ts";

// ---------------------------------------------------------------------------
// Cookie
// ---------------------------------------------------------------------------

/** Name of the session cookie. */
export const SESSION_COOKIE = "cloudsentinel_session";

/**
 * Attributes applied to the session cookie.
 *
 * Every one of these is load-bearing:
 *
 * - **`httpOnly`** — the cookie is invisible to `document.cookie`, so a script
 *   injected into the page cannot read the token and send it elsewhere. This is
 *   the single most valuable attribute here and the reason a cookie was chosen
 *   over `localStorage` at all.
 *
 * - **`sameSite: "strict"`** — the browser attaches this cookie only to
 *   requests originating from CloudSentinel's own pages. That is the defence
 *   against cross-site request forgery: without it, a page on another site
 *   could POST to the triage endpoint and the browser would helpfully include
 *   the session cookie, letting an attacker suppress findings on behalf of
 *   whoever visited their page.
 *
 *   `strict` rather than `lax` because `lax` still sends the cookie on
 *   top-level navigations from other sites. The cost is that following a link
 *   into the dashboard from an email or chat lands on the login page even
 *   though the session is live; a refresh fixes it. For an internal security
 *   dashboard that is a fair price, and this project prefers the safer default
 *   where the two conflict.
 *
 * - **`secure`** — in production the cookie is only ever sent over HTTPS, so it
 *   cannot be captured from plaintext traffic. It is disabled in development
 *   because the dev server is plain HTTP on localhost.
 *
 * - **`path: "/"`** — the whole application shares one session.
 *
 * - **`maxAge`** — matched to the token's own lifetime so the cookie and the
 *   token expire together. A cookie outliving its token would leave the browser
 *   sending something guaranteed to be rejected; a token outliving its cookie
 *   would be a session that vanishes while still valid.
 */
function cookieOptions(maxAge: number) {
  return {
    httpOnly: true,
    sameSite: "strict" as const,
    // NODE_ENV is set to "production" by `next build` / `next start`, and to
    // "development" by `next dev`. Deriving the flag rather than hard-coding it
    // means the secure cookie cannot be forgotten on deploy.
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge,
  };
}

// ---------------------------------------------------------------------------
// Issuing and clearing
// ---------------------------------------------------------------------------

/**
 * Signs a token for a user and sets it as the session cookie.
 *
 * The token's claims are read from the user record at this moment. They are not
 * trusted later on their own — {@link currentUser} re-checks them against the
 * database on every request — but they must be correct here, because the
 * `tv` claim is what ties the token to a specific revocation generation.
 *
 * @param user - the freshly authenticated user.
 * @throws if `CLOUDSENTINEL_JWT_SECRET` is unset or too short.
 */
export async function issueSession(user: User): Promise<void> {
  const token = signToken({
    sub: String(user.id),
    email: user.email,
    role: user.role,
    tv: user.tokenVersion,
  });

  const store = await cookies();
  store.set(SESSION_COOKIE, token, cookieOptions(TOKEN_LIFETIME_SECONDS));
}

/**
 * Removes the session cookie.
 *
 * Note what this does *not* do: it cannot invalidate the token itself, because
 * a JWT is valid until it expires and the server keeps no record of it. This
 * only asks the browser to forget its copy. A token already copied elsewhere
 * keeps working until `exp`.
 *
 * That is the honest limitation of stateless sessions, and it is why
 * `revokeSessions` in lib/db/users.ts exists: "log out on this device" and
 * "invalidate every session everywhere" are genuinely different operations, and
 * this is only the first one.
 */
export async function clearSession(): Promise<void> {
  const store = await cookies();
  // Overwritten with an empty value and a zero lifetime rather than only
  // deleted, so a browser that ignores the delete still holds nothing usable.
  store.set(SESSION_COOKIE, "", cookieOptions(0));
  store.delete(SESSION_COOKIE);
}

// ---------------------------------------------------------------------------
// Reading the current identity
// ---------------------------------------------------------------------------

/**
 * Resolves the user making the current request, or `null`.
 *
 * Three checks, in this order, and the order matters:
 *
 *   1. the cookie exists;
 *   2. the token's signature verifies and it has not expired
 *      (lib/auth/jwt.ts);
 *   3. the claims still agree with the database — the account exists, the
 *      session was not revoked, and the role has not changed
 *      (`userForClaims` in lib/db/users.ts).
 *
 * Step 3 is what makes the whole scheme safe. A verified token proves only that
 * we issued it and nobody altered it; it says nothing about the eight hours
 * since. Skipping the database lookup would be faster and would leave a
 * revoked, deleted, or demoted user with a working session until their token
 * expired.
 *
 * @returns the current user, or `null` for any failure. The failures are
 *   deliberately indistinguishable to the caller — a missing cookie, a forged
 *   token, and a revoked session all produce the same `null`, and therefore the
 *   same response, so nothing about the reply tells an attacker which of those
 *   they achieved.
 */
export async function currentUser(): Promise<User | null> {
  const store = await cookies();
  const token = store.get(SESSION_COOKIE)?.value;
  if (!token) return null;

  const result = verifyToken(token);
  if (!result.valid) return null;

  return userForClaims(result.claims);
}

/**
 * Reloads a user record by id, for callers that already know who they are.
 *
 * Exists so a route that has just changed something about the current user can
 * see the change without re-reading the cookie.
 */
export async function reloadUser(id: number): Promise<User | null> {
  return findUserById(id);
}
