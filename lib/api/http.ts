/**
 * CloudSentinel — shared HTTP helpers for the API routes.
 *
 * One place for JSON responses, error shapes, request-body parsing, and the
 * cross-site request check that every state-changing route begins with.
 *
 * Where it sits in the architecture: a leaf. Everything here is a pure function
 * of its arguments, so it depends on nothing else in the project.
 *
 *   app/api/<name>/route.ts --> [ this file ]
 *
 * ## Why the session guards are NOT in this file
 *
 * `requireUser()` and `requireAdmin()` live in lib/api/guards.ts. The split is
 * not organisational tidiness — it is a module boundary with a purpose.
 *
 * Everything in this file is a pure function of its arguments: it reads no
 * cookie, opens no connection, and imports nothing that needs a Next.js
 * runtime. The guards cannot be, because they must read the session cookie via
 * `next/headers` and then query Postgres.
 *
 * Keeping them together made this file untestable. A test importing it to check
 * one header comparison pulled in `next/headers`, which does not resolve
 * outside a Next server, and the whole suite failed to load. That is the same
 * class of mistake phase 5 hit from the other direction, when a client
 * component imported from lib/db/triage.ts and the bundler tried to put the
 * PostgreSQL driver into a browser bundle — a module that mixes a pure concern
 * with a runtime-bound one drags the runtime everywhere it is used.
 *
 * The guards are deliberately NOT re-exported from here for convenience. That
 * was tried and it silently undid the whole split: a re-export is still an
 * import, so `http.ts` went on pulling `next/headers` into everything that
 * touched it and the tests failed exactly as before. A module boundary that
 * exists to keep a dependency out cannot also forward that dependency. Routes
 * import guards from lib/api/guards.ts directly.
 *
 * ## Why error responses are vague
 *
 * Every failure below answers with a generic message and a stable machine
 * code. Telling a client that the email exists but the password was wrong, or
 * that the token's signature failed rather than that it expired, is free
 * reconnaissance. The detail goes to the server log, where the operator can see
 * it and an attacker cannot.
 */

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
// Cross-site request forgery
// ---------------------------------------------------------------------------

/**
 * Rejects a state-changing request that did not originate from this site.
 *
 * ## What this defends against
 *
 * A cross-site request forgery works by making the *victim's own browser* issue
 * a request. A hostile page submits a form or fires a `fetch` at this API, the
 * browser helpfully attaches the session cookie because cookies are scoped to
 * the destination rather than the initiator, and the request arrives fully
 * authenticated. In this application the prize is the triage endpoint: an
 * attacker who can get a signed-in administrator to visit a page can suppress
 * findings on their behalf, quietly removing real problems from the default
 * view while the scanner goes on reporting the bucket is public.
 *
 * ## Why this exists when the cookie is already `SameSite=strict`
 *
 * `SameSite=strict` (see lib/auth/session.ts) is the primary defence and it is a
 * good one: the browser will not attach the session cookie to a request started
 * by another site at all. This check is deliberately a second layer, because the
 * first one is enforced entirely by the client and this project does not get to
 * choose the client.
 *
 * Three concrete gaps it covers:
 *
 *   - A browser that does not implement `SameSite`, or a request made by
 *     something that is not a browser and does not honour it.
 *   - A same-site attacker. `SameSite` is *site*, not *origin* — it uses the
 *     registrable domain, so a hostile page on a sibling subdomain, or one
 *     served over plain HTTP against an HTTPS deployment, counts as same-site
 *     and its requests carry the cookie. `Origin` distinguishes those; the
 *     cookie attribute cannot.
 *   - A future change that relaxes the cookie to `SameSite=lax` — under which
 *     top-level form posts from another site do carry the cookie — without
 *     anyone noticing the protection was load-bearing.
 *
 * ## Why `Origin` and not `Referer`
 *
 * `Origin` is sent on exactly the requests that matter, contains only the
 * scheme, host and port, and cannot be suppressed by a privacy setting the way
 * `Referer` routinely is. Validating `Referer` means either rejecting the many
 * legitimate requests that omit it or accepting its absence, which reduces the
 * check to nothing.
 *
 * ## The absent-header decision
 *
 * A missing `Origin` is **rejected**, not allowed through. Browsers always send
 * it on the cross-origin and `POST` requests this guards, so absence means the
 * caller is not a browser doing an ordinary form submission — a script, a
 * command-line client, or something forging a request. Allowing it would leave
 * an opt-out that consists of simply not sending a header, which is not a
 * control at all. The cost is that `curl` must pass `-H "Origin: <site>"` to
 * call a write endpoint, which is documented in the README.
 *
 * @param request - the incoming request. Its `Origin` header is compared with
 *   the `Host` this request was actually addressed to, so no environment
 *   variable has to be kept in step with where the app is deployed — the
 *   comparison is self-referential and correct on localhost, on a NodePort, and
 *   behind a domain name without configuration.
 * @returns `null` when the request may proceed, or the 403 response to return.
 */
export function checkSameOrigin(request: Request): Response | null {
  const origin = request.headers.get("origin");
  if (!origin) {
    return forbidden(
      "This request is missing an Origin header and was refused. " +
        "State-changing requests must be made from the dashboard.",
    );
  }

  // `Host` is what the client asked for, which is the same value the browser
  // used to build `Origin`, so the two are directly comparable. Taking the
  // expected host from the request rather than from configuration is what makes
  // this work unchanged across localhost, the Kubernetes NodePort, and any
  // hostname a real deployment uses.
  //
  // Note the trust boundary: behind a reverse proxy, `Host` is whatever the
  // proxy forwards, so this check is only as trustworthy as that proxy. That is
  // the same assumption `lib/api/rate-limit.ts` documents for
  // `x-forwarded-for`, and it is acceptable for the same reason — a proxy that
  // forwards an attacker-chosen Host is already misconfigured in a way that
  // breaks more than this.
  const host = request.headers.get("host");
  if (!host) {
    return forbidden("This request is missing a Host header and was refused.");
  }

  let originHost: string;
  try {
    // Parsed rather than string-compared. `"https://example.com"` and
    // `"https://example.com:443"` name the same origin, and a substring test
    // would also accept `"https://example.com.attacker.test"` — a classic way
    // for an origin check to look right and do nothing.
    originHost = new URL(origin).host;
  } catch {
    return forbidden("This request has a malformed Origin header.");
  }

  if (originHost !== host) {
    // The mismatch is not echoed back. Reflecting the value an attacker sent
    // into a response body is a habit worth not having, and the operator can
    // see the request in the access log.
    return forbidden(
      "This request came from another site and was refused.",
    );
  }

  return null;
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
