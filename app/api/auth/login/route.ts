/**
 * CloudSentinel — POST /api/auth/login
 *
 * Exchanges an email and password for a session cookie. The only unauthenticated
 * write endpoint in the application, and therefore the one worth the most care.
 *
 * Where it sits in the architecture:
 *
 *   login form (app/login) --> [ this route ] --> lib/api/rate-limit.ts
 *                                             --> lib/db/users.ts authenticate()
 *                                             --> lib/auth/session.ts issueSession()
 *
 * Request:  { "email": "you@example.com", "password": "..." }
 * Response: 200 { "user": { "id", "email", "role" } } and a Set-Cookie header,
 *           or 401 with a generic message.
 *
 * There is deliberately no matching sign-up route. Accounts are created only
 * with `npm run user:create`, because a security dashboard that lets anonymous
 * visitors register themselves an account is not one worth running.
 *
 * ## Four defences, and what each is for
 *
 * 1. **Rate limiting**, before anything expensive happens. scrypt makes offline
 *    cracking costly but does nothing about an attacker simply asking this
 *    endpoint repeatedly — and because each attempt costs the *server* ~100 ms
 *    of CPU, an unthrottled login is also a denial-of-service amplifier.
 *
 * 2. **A uniform failure response.** A wrong password and an email with no
 *    account produce byte-identical replies. Distinguishing them turns this
 *    endpoint into an oracle for which addresses hold accounts.
 *
 * 3. **Uniform failure *timing*.** Handled in `authenticate` (lib/db/users.ts),
 *    which verifies against a decoy hash when no row matches so an unknown
 *    email costs the same as a known one. An identical message delivered in a
 *    hundredth of the time leaks the same fact.
 *
 * 4. **No password in any log line.** The body is never logged, and failures
 *    are recorded with the email and the client key only.
 */

import {
  apiError,
  invalidInput,
  json,
  rawStringField,
  readJson,
  stringField,
} from "../../../../lib/api/http.ts";
import {
  checkRateLimit,
  clientKey,
  resetRateLimit,
} from "../../../../lib/api/rate-limit.ts";
import { issueSession } from "../../../../lib/auth/session.ts";
import { authenticate } from "../../../../lib/db/users.ts";

/**
 * Longest password accepted at the login form.
 *
 * Generous enough for any real passphrase, and low enough that the scrypt call
 * behind it can never be handed a payload large enough to be a weapon.
 */
const MAX_PASSWORD_LENGTH = 512;

/** Longest email accepted. 320 is the maximum length permitted by RFC 5321. */
const MAX_EMAIL_LENGTH = 320;

export async function POST(request: Request): Promise<Response> {
  const key = clientKey(request);

  // Checked first, deliberately: before the body is parsed and long before
  // scrypt runs. A limiter that only engages after the expensive work has
  // happened does not prevent the resource exhaustion it exists to prevent.
  const limit = checkRateLimit(key);
  if (!limit.allowed) {
    return new Response(
      JSON.stringify({
        error: {
          code: "rate_limited",
          message: "Too many sign-in attempts. Try again shortly.",
        },
      }),
      {
        status: 429,
        headers: {
          "Content-Type": "application/json",
          // Tells a well-behaved client when to come back, instead of leaving
          // it to retry in a tight loop and make things worse.
          "Retry-After": String(limit.retryAfterSeconds),
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
        },
      },
    );
  }

  const body = await readJson(request);
  const email = stringField(body, "email", MAX_EMAIL_LENGTH);
  const password = rawStringField(body, "password", MAX_PASSWORD_LENGTH);

  if (!email || !password) {
    // A 400 here is safe: it says the request was malformed, not whether the
    // account exists. Anything an attacker learns from it, they already knew,
    // since they control the body.
    return invalidInput("An email address and password are required.");
  }

  const user = await authenticate(email, password);

  if (!user) {
    // One message for both "no such account" and "wrong password".
    //
    // The email is logged so a real operator can see an attack building; the
    // password never is. Note this runs server-side only — the client receives
    // the response below and nothing else.
    console.warn(
      `[auth] failed sign-in for ${email} from ${key} ` +
        `(${limit.remaining} attempts remaining in window)`,
    );
    return apiError(401, "unauthenticated", "Incorrect email or password.");
  }

  // Cleared on success so someone who mistyped their password twice is not
  // still throttled once they get it right. The budget exists to slow guessing,
  // not to punish typing.
  resetRateLimit(key);

  await issueSession(user);

  // Only the fields the UI needs. No token in the body — it is in an httpOnly
  // cookie precisely so that page scripts cannot reach it, and echoing it here
  // would hand it straight back to any script on the page and undo that.
  return json({
    user: { id: user.id, email: user.email, role: user.role },
  });
}
