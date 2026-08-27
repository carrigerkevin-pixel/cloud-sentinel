/**
 * CloudSentinel — session guards for the API routes.
 *
 * The two functions every protected route begins with: one requiring any
 * signed-in user, one requiring an administrator.
 *
 * Where it sits in the architecture:
 *
 *   app/api/<name>/route.ts --> [ this file ] --> lib/auth/session.ts --> Postgres
 *
 * They are re-exported from lib/api/http.ts, so routes import them from there
 * alongside the response helpers and no call site names this file directly.
 *
 * ## Why this is a separate file from lib/api/http.ts
 *
 * These guards read the session cookie through `next/headers` and then query
 * the database. That makes them unusable outside a Next.js server — importing
 * them from a plain Node test fails to resolve `next/headers` at all.
 *
 * lib/api/http.ts is pure by contrast, and keeping it that way is what lets its
 * response builders and the cross-site request check be tested directly. Mixing
 * the two in one module made the pure half untestable, which is how this split
 * came about.
 *
 * ## Why the guards are here rather than in middleware
 *
 * Next.js middleware (now `proxy.ts`) is the obvious place to put an auth
 * check, and it is the wrong one for this application. It runs on the Edge
 * runtime, which has no `node:crypto` and no TCP sockets — so it can neither
 * verify an HS256 signature with the code in lib/auth/jwt.ts nor make the
 * database round trip that `userForClaims` needs to catch a revoked session. A
 * check there would end up trusting the token's own claims, which is exactly
 * the shortcut this project set out not to take.
 *
 * The trade-off is that protection is opt-in per route rather than applied by
 * default, and a new route that forgets {@link requireUser} is unprotected. The
 * mitigation is that there is exactly one way to write a protected route and
 * every existing route follows it, so an unguarded one is visible in review.
 */

import { currentUser } from "../auth/session.ts";
import type { User } from "../db/users.ts";
import { forbidden, unauthenticated } from "./http.ts";

/**
 * The result of a guard: either an authenticated user, or the response to
 * return immediately.
 *
 * A discriminated union rather than a thrown exception, because TypeScript then
 * refuses to let a route reach `result.user` without having handled
 * `result.response` first. A guard that can be ignored by forgetting a
 * `try`/`catch` is a guard that eventually is.
 */
export type Guarded =
  | { ok: true; user: User }
  | { ok: false; response: Response };

/**
 * Requires any signed-in user.
 *
 * Every read endpoint starts with this. It performs the full check —
 * signature, expiry, and a database lookup confirming the session has not been
 * revoked and the account still exists.
 *
 * @example
 * const guard = await requireUser();
 * if (!guard.ok) return guard.response;
 * // guard.user is available and current from here on.
 */
export async function requireUser(): Promise<Guarded> {
  const user = await currentUser();
  if (!user) return { ok: false, response: unauthenticated() };
  return { ok: true, user };
}

/**
 * Requires a signed-in administrator.
 *
 * Used by every endpoint that changes state — currently the triage routes.
 *
 * The role is taken from the freshly-loaded database record, not from the
 * token's claim. That distinction is the whole point: `userForClaims` already
 * refuses a token whose role no longer matches the database, so a demoted
 * administrator cannot reach this at all, and this function cannot be fooled by
 * a stale claim even if that check were ever relaxed.
 *
 * An authenticated non-admin gets 403 rather than 401, because 401 would send
 * the client back to a login page that cannot help — they are already signed
 * in, and signing in again will not grant the role.
 */
export async function requireAdmin(): Promise<Guarded> {
  const guard = await requireUser();
  if (!guard.ok) return guard;

  if (guard.user.role !== "admin") {
    return {
      ok: false,
      response: forbidden("Changing triage state requires an admin account."),
    };
  }

  return guard;
}
