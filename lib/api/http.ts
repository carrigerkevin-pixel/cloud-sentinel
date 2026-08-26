/**
 * CloudSentinel — shared HTTP helpers for the API routes.
 *
 * One place for JSON responses, error shapes, and the authentication and
 * authorization guards every protected route begins with.
 *
 * Where it sits in the architecture:
 *
 *   app/api/<name>/route.ts --> [ this file ] --> lib/auth/session.ts --> Postgres
 *
 * ## Why the guards live here rather than in middleware
 *
 * Next.js middleware is the obvious place to put an auth check, and it is the
 * wrong one for this application. Middleware runs on the Edge runtime, which
 * has no `node:crypto` and no TCP sockets — so it can neither verify an HS256
 * signature with the code in lib/auth/jwt.ts nor make the database round trip
 * that `userForClaims` needs to catch a revoked session. A middleware check
 * would end up trusting the token's own claims, which is exactly the shortcut
 * this project set out not to take.
 *
 * The trade-off is that protection is opt-in per route rather than applied by
 * default, and a new route that forgets {@link requireUser} is unprotected. The
 * mitigation is that there is exactly one way to write a protected route and
 * every existing route follows it, so an unguarded one is visible in review.
 *
 * ## Why error responses are vague
 *
 * Every failure below answers with a generic message and a stable machine
 * code. Telling a client that the email exists but the password was wrong, or
 * that the token's signature failed rather than that it expired, is free
 * reconnaissance. The detail goes to the server log, where the operator can see
 * it and an attacker cannot.
 */

import { currentUser } from "../auth/session.ts";
import type { User } from "../db/users.ts";

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/**
 * Machine-readable error codes.
 *
 * A stable code lets the client branch on the outcome — redirecting to the
 * login page on `unauthenticated`, showing an inline message on `invalid_input`
 * — without parsing English prose that may be reworded later.
 */
export type ApiErrorCode =
  | "unauthenticated"
  | "forbidden"
  | "invalid_input"
  | "not_found"
  | "rate_limited"
  | "conflict"
  | "server_error";

/** The body every error response carries. */
export interface ApiErrorBody {
  error: { code: ApiErrorCode; message: string };
}

/** Builds a JSON response. */
export function json<T>(data: T, status = 200): Response {
  return Response.json(data, {
    status,
    headers: {
      // The API returns data, never a document. Telling the browser not to
      // second-guess the content type closes off MIME-sniffing tricks that turn
      // a JSON response containing attacker-influenced strings — resource names
      // and ARNs, here — into something the browser renders as HTML.
      "X-Content-Type-Options": "nosniff",
      // Findings describe live security weaknesses. They must never sit in a
      // shared cache or a browser's disk cache after the user logs out.
      "Cache-Control": "no-store",
    },
  });
}

/** Builds a JSON error response with a stable code. */
export function apiError(
  status: number,
  code: ApiErrorCode,
  message: string,
): Response {
  return json<ApiErrorBody>({ error: { code, message } }, status);
}

/** 401. Deliberately identical whatever the underlying reason. */
export function unauthenticated(): Response {
  return apiError(401, "unauthenticated", "Sign in to continue.");
}

/** 403. The caller is known but not permitted. */
export function forbidden(message = "You do not have access to do that."): Response {
  return apiError(403, "forbidden", message);
}

/** 400, for a malformed or invalid request body. */
export function invalidInput(message: string): Response {
  return apiError(400, "invalid_input", message);
}

/** 404. */
export function notFound(message = "Not found."): Response {
  return apiError(404, "not_found", message);
}

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

/**
 * Parses a JSON request body without throwing.
 *
 * A malformed body arrives from the network and must produce a 400, not an
 * unhandled rejection that Next.js turns into a 500. A 500 also implies the
 * server is broken, which invites a retry of something that will never succeed.
 *
 * @returns the parsed value, or `null` if the body was absent or not JSON. The
 *   result is typed `unknown` on purpose — the caller must narrow it, because
 *   nothing about a network request guarantees its shape.
 */
export async function readJson(request: Request): Promise<unknown | null> {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

/**
 * Extracts a trimmed, non-empty string field from a parsed body.
 *
 * @returns the string, or `null` if the field is missing, not a string, empty,
 *   or longer than `maxLength`.
 *
 * The length ceiling is not cosmetic: without one, a client can post a
 * multi-megabyte string that gets hashed, stored, or rendered. On the login
 * route in particular an unbounded password would be handed to scrypt, turning
 * one request into an arbitrarily expensive computation — a denial of service
 * with no authentication required.
 */
export function stringField(
  body: unknown,
  field: string,
  maxLength = 1024,
): string | null {
  if (typeof body !== "object" || body === null) return null;

  const value = (body as Record<string, unknown>)[field];
  if (typeof value !== "string") return null;

  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > maxLength) return null;

  return trimmed;
}

/**
 * Extracts a string field **without trimming it**.
 *
 * Used for passwords, and only for passwords. Trimming a password silently
 * changes it: a passphrase that legitimately ends in a space would be stored
 * one way at account creation and compared another way at login, producing an
 * account whose owner cannot sign in and no error message that explains why.
 * Whitespace is a legal password character and this project does not quietly
 * edit what the user typed.
 *
 * The length ceiling still applies, and matters more here than elsewhere: an
 * unbounded password goes straight into scrypt, and a multi-megabyte one turns
 * a single unauthenticated request into an arbitrarily expensive computation.
 *
 * @returns the string exactly as sent, or `null` if it is missing, not a
 *   string, empty, or over `maxLength`.
 */
export function rawStringField(
  body: unknown,
  field: string,
  maxLength = 1024,
): string | null {
  if (typeof body !== "object" || body === null) return null;

  const value = (body as Record<string, unknown>)[field];
  if (typeof value !== "string") return null;
  if (value.length === 0 || value.length > maxLength) return null;

  return value;
}
