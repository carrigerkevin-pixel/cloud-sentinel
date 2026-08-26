/**
 * CloudSentinel — JSON Web Token signing and verification (HS256).
 *
 * Issues the token the dashboard uses to prove who is making a request, and
 * checks tokens coming back in. Implemented directly on `node:crypto` rather
 * than pulling in a JWT library.
 *
 * Where it sits in the architecture:
 *
 *   POST /api/auth/login --> lib/auth/password.ts verifies the password
 *                        --> [ this file ] signs a token
 *                        --> httpOnly cookie
 *
 *   any authenticated request --> [ this file ] verifies the token
 *                             --> lib/auth/session.ts re-checks it against the
 *                                 user row (role, token_version)
 *
 * ## What a JWT actually is
 *
 * Three base64url-encoded parts joined by dots:
 *
 *   <header>.<payload>.<signature>
 *
 * The header names the algorithm. The payload is the claims — who the user is,
 * when the token expires. Both are merely *encoded*, *not encrypted*: anyone
 * holding the token can read them. Nothing secret ever goes in a JWT payload.
 *
 * The signature is an HMAC-SHA256 of `<header>.<payload>` under a secret only
 * the server knows. That is the entire security model: the contents are public,
 * but they cannot be changed without the secret, so a client cannot edit
 * `"role": "viewer"` into `"role": "admin"` and have it accepted.
 *
 * ## Why hand-rolled
 *
 * Two reasons. It keeps the dependency count at zero, matching the rest of this
 * project (Node's built-in test runner, no test framework, no ORM). And the
 * verification path below is the part of JWT that libraries exist to get right,
 * so writing it deliberately — with the historical attacks named and rejected
 * in code — is the point rather than an accident.
 *
 * ## The two attacks this file exists to reject
 *
 * **`alg: none`.** The JWT specification includes an "unsecured" mode where the
 * algorithm is `none` and the signature is empty. An attacker takes a valid
 * token, rewrites the payload to make themselves an admin, sets the header to
 * `{"alg":"none"}`, and deletes the signature. A verifier that reads the
 * algorithm out of the header and does what it says will accept it, because the
 * token honestly declares it is unsigned. This is not hypothetical — it was a
 * real vulnerability in several major JWT libraries in 2015.
 *
 * **Algorithm confusion.** The same trick with `RS256` swapped for `HS256`. If
 * a server verifies with an RSA *public* key but the attacker declares the
 * algorithm to be HMAC, a naive verifier uses that public key as the HMAC
 * secret — and the public key is, by definition, public.
 *
 * The defence for both is the same one line, and it is the reason the algorithm
 * is never read from the header at all: this file decides what the algorithm is
 * before it looks at the token, and rejects anything that disagrees.
 */

import { createHmac, timingSafeEqual } from "node:crypto";

import { loadEnvFile } from "../util/env.ts";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * The only algorithm accepted, in either direction.
 *
 * Hard-coded rather than configurable. A knob here would be a knob an attacker
 * eventually finds a way to turn.
 */
const ALGORITHM = "HS256" as const;

/** Environment variable holding the signing secret. */
const SECRET_ENV = "CLOUDSENTINEL_JWT_SECRET";

/**
 * Shortest secret accepted, in characters.
 *
 * HMAC-SHA256 has a 256-bit security level, so a secret shorter than 32 bytes
 * is the weakest link in the chain — and a short one is usually a short one
 * because somebody typed a word. Refusing to start is better than running with
 * a signing key that can be guessed, because nothing about the running system
 * would look wrong.
 */
const MIN_SECRET_LENGTH = 32;

/** How long an issued token stays valid, in seconds. */
export const TOKEN_LIFETIME_SECONDS = 8 * 60 * 60;

/**
 * Clock skew tolerated when checking `iat`, in seconds.
 *
 * A token is rejected if it claims to have been issued in the future, which
 * would indicate tampering — but "the future" has to allow for the issuing and
 * verifying clocks disagreeing slightly. Sixty seconds is generous for a system
 * where both sides are the same process, and small enough to be no help to an
 * attacker.
 */
const CLOCK_SKEW_SECONDS = 60;

// ---------------------------------------------------------------------------
// Claims
// ---------------------------------------------------------------------------

/**
 * What CloudSentinel puts in a token.
 *
 * Everything here is readable by anyone holding the token, so it contains
 * identity and authorization facts only — never a password hash, a database
 * credential, or anything about the scanned environment.
 */
export interface TokenClaims {
  /** Subject: the `users.id` this token was issued for, as a string per the JWT spec. */
  sub: string;

  /** The user's email. Carried for display, so the UI need not query for a name. */
  email: string;

  /** Role at issue time. Re-checked against the database on every request. */
  role: "admin" | "viewer";

  /**
   * The `users.token_version` this token was issued under.
   *
   * SECURITY: this is the revocation mechanism. A signed token is valid until
   * it expires and the server keeps no record of it, so there is otherwise no
   * way to cancel one early. Comparing this claim against the current column
   * value turns "bump an integer" into "every token that user holds stops
   * working immediately" — which is what logging out of all devices, and
   * responding to a suspected compromise, both require.
   */
  tv: number;

  /** Issued at, seconds since the Unix epoch. */
  iat: number;

  /** Expires at, seconds since the Unix epoch. */
  exp: number;
}

/** The caller-supplied part of a token. `iat` and `exp` are set by {@link signToken}. */
export type IssuableClaims = Omit<TokenClaims, "iat" | "exp">;

// ---------------------------------------------------------------------------
// Secret
// ---------------------------------------------------------------------------

/**
 * Reads the signing secret from the environment.
 *
 * There is deliberately no fallback value. A development default would be
 * committed to this repository, which would mean anyone who read the source
 * could mint valid admin tokens against any deployment that had not overridden
 * it — and the ones that forget to override it are exactly the ones nobody is
 * watching. Failing to start is the safe behaviour.
 *
 * @returns the secret as a buffer, ready for HMAC.
 * @throws if the variable is unset or shorter than {@link MIN_SECRET_LENGTH}.
 *   The error names the variable and explains how to generate a value, but
 *   never quotes what was found — that value is the credential.
 */
function signingSecret(): Buffer {
  // Reads .env once, without overwriting anything already set in the real
  // environment. Called here rather than at module scope so that importing this
  // file has no side effects and a test can set its own value first.
  loadEnvFile();

  const secret = process.env[SECRET_ENV];

  if (!secret) {
    throw new Error(
      `${SECRET_ENV} is not set, so no token can be signed or verified. ` +
        "Generate one with:\n" +
        '  node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'base64\'))"\n' +
        "then add it to .env.",
    );
  }

  if (secret.length < MIN_SECRET_LENGTH) {
    throw new Error(
      `${SECRET_ENV} is too short: it must be at least ${MIN_SECRET_LENGTH} ` +
        "characters. Generate a random value rather than choosing one — a " +
        "guessable signing key lets anyone forge an admin session.",
    );
  }

  return Buffer.from(secret, "utf8");
}

// ---------------------------------------------------------------------------
// base64url
// ---------------------------------------------------------------------------

/**
 * Encodes to base64url: the URL-safe base64 variant JWT uses.
 *
 * Standard base64's `+`, `/`, and `=` all have meanings in URLs and cookies, so
 * JWT substitutes `-` and `_` and drops the padding entirely.
 */
function base64UrlEncode(input: Buffer | string): string {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Decodes base64url back to bytes.
 *
 * Node's decoder ignores characters it does not recognise, so it will happily
 * decode a string containing junk instead of reporting it. That leniency is a
 * problem here: two different token strings could decode to the same bytes,
 * which is the shape of a signature-confusion bug. So the input is validated
 * against the base64url alphabet first.
 *
 * @returns the decoded bytes, or `null` if the input is not valid base64url.
 */
function base64UrlDecode(input: string): Buffer | null {
  if (input.length === 0 || !/^[A-Za-z0-9_-]+$/.test(input)) return null;

  const padded = input
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(input.length / 4) * 4, "=");

  return Buffer.from(padded, "base64");
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/** Computes the signature over the `<header>.<payload>` portion of a token. */
function sign(signingInput: string, secret: Buffer): string {
  return base64UrlEncode(createHmac("sha256", secret).update(signingInput).digest());
}

/**
 * Issues a signed token.
 *
 * `iat` and `exp` are set here rather than accepted from the caller, so no code
 * path can accidentally mint a token that never expires — the single most
 * common way a JWT deployment goes wrong. A stolen token is only dangerous
 * until it expires, and "never" is a bad value for that.
 *
 * @param claims - identity and authorization facts. Must contain nothing
 *   secret: the payload is encoded, not encrypted, and is readable by anyone
 *   holding the token.
 * @param lifetimeSeconds - how long the token remains valid. Defaults to
 *   {@link TOKEN_LIFETIME_SECONDS}.
 * @returns the encoded `header.payload.signature` string.
 * @throws if {@link SECRET_ENV} is unset or too short.
 */
export function signToken(
  claims: IssuableClaims,
  lifetimeSeconds: number = TOKEN_LIFETIME_SECONDS,
): string {
  const secret = signingSecret();
  const now = Math.floor(Date.now() / 1000);

  const header = { alg: ALGORITHM, typ: "JWT" };
  const payload: TokenClaims = {
    ...claims,
    iat: now,
    exp: now + lifetimeSeconds,
  };

  const signingInput =
    `${base64UrlEncode(JSON.stringify(header))}.` +
    `${base64UrlEncode(JSON.stringify(payload))}`;

  return `${signingInput}.${sign(signingInput, secret)}`;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/**
 * Why a token was rejected.
 *
 * Returned to the caller for logging. It is deliberately *not* sent to the
 * client: telling an attacker whether their forgery failed on the signature or
 * on the expiry is free feedback on how close they are. The API answers every
 * one of these with the same generic 401.
 */
export type VerifyFailure =
  | "malformed"
  | "unsupported_algorithm"
  | "bad_signature"
  | "expired"
  | "issued_in_future"
  | "invalid_claims";

/** The outcome of verifying a token. A discriminated union, so claims are only reachable when valid. */
export type VerifyResult =
  | { valid: true; claims: TokenClaims }
  | { valid: false; reason: VerifyFailure };

/**
 * Verifies a token and returns its claims.
 *
 * The order of operations matters and is the reason this function reads the way
 * it does: **nothing in the payload is trusted until the signature has been
 * checked.** Expiry, role, and user id are all attacker-controlled strings
 * until the HMAC says otherwise, so the signature check comes first and every
 * other check comes after.
 *
 * @param token - the raw `header.payload.signature` string from the cookie.
 * @returns a result carrying either the verified claims or a machine-readable
 *   reason. Never throws for a bad token — only for a misconfigured secret,
 *   which is a server fault rather than a client one and must not be reported
 *   as a failed login.
 */
export function verifyToken(token: string): VerifyResult {
  const secret = signingSecret();

  const parts = token.split(".");
  if (parts.length !== 3) return { valid: false, reason: "malformed" };

  const [encodedHeader, encodedPayload, providedSignature] = parts as [
    string,
    string,
    string,
  ];

  // SECURITY: the algorithm is decided here, not read from the token.
  //
  // The expected signature is computed with HS256 unconditionally. A token
  // declaring `alg: none` with an empty signature, or `alg: RS256` hoping the
  // public key gets used as an HMAC secret, produces a signature that does not
  // match and is rejected below like any other forgery. The header is still
  // parsed and checked, but as a sanity check — the security does not rest on
  // it.
  const expectedSignature = sign(`${encodedHeader}.${encodedPayload}`, secret);

  const provided = Buffer.from(providedSignature, "utf8");
  const expected = Buffer.from(expectedSignature, "utf8");

  // Length is checked separately because timingSafeEqual throws on a mismatch
  // rather than returning false. This leaks nothing: the length of an HMAC-SHA256
  // signature is fixed by the algorithm, not by the secret.
  if (provided.length !== expected.length) {
    return { valid: false, reason: "bad_signature" };
  }

  // Constant-time. A byte-by-byte comparison that returns early would leak how
  // much of a forged signature was correct through response timing, which over
  // enough attempts is enough to construct a valid one.
  if (!timingSafeEqual(provided, expected)) {
    return { valid: false, reason: "bad_signature" };
  }

  // --- Past this line the token is known to be ours and unmodified. ---

  const headerBytes = base64UrlDecode(encodedHeader);
  const payloadBytes = base64UrlDecode(encodedPayload);
  if (!headerBytes || !payloadBytes) {
    return { valid: false, reason: "malformed" };
  }

  let header: unknown;
  let payload: unknown;
  try {
    header = JSON.parse(headerBytes.toString("utf8"));
    payload = JSON.parse(payloadBytes.toString("utf8"));
  } catch {
    return { valid: false, reason: "malformed" };
  }

  if (
    typeof header !== "object" ||
    header === null ||
    (header as { alg?: unknown }).alg !== ALGORITHM
  ) {
    return { valid: false, reason: "unsupported_algorithm" };
  }

  const claims = payload as Partial<TokenClaims>;

  if (
    typeof claims.sub !== "string" ||
    claims.sub.length === 0 ||
    typeof claims.email !== "string" ||
    (claims.role !== "admin" && claims.role !== "viewer") ||
    typeof claims.tv !== "number" ||
    !Number.isInteger(claims.tv) ||
    typeof claims.iat !== "number" ||
    typeof claims.exp !== "number"
  ) {
    return { valid: false, reason: "invalid_claims" };
  }

  const now = Math.floor(Date.now() / 1000);

  if (claims.exp <= now) {
    return { valid: false, reason: "expired" };
  }

  // A token claiming to have been issued in the future is not something a
  // correct client produces. It is reported separately from `expired` so the
  // two are distinguishable in the server log, where the distinction is a
  // useful signal that somebody is experimenting.
  if (claims.iat > now + CLOCK_SKEW_SECONDS) {
    return { valid: false, reason: "issued_in_future" };
  }

  return { valid: true, claims: claims as TokenClaims };
}
