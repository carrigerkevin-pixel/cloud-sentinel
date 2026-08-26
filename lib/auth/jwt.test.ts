/**
 * CloudSentinel — tests for JWT signing and verification.
 *
 * Run with `npm test`. Pure crypto, no database and no network.
 *
 * Roughly two thirds of this file is forgery attempts. That balance is
 * intentional: the happy path of a JWT is trivial and hard to get wrong, while
 * every historically serious JWT vulnerability lived in the verification path —
 * `alg: none`, algorithm confusion, unchecked expiry, non-constant-time
 * comparison. A suite that only proved a valid token round-trips would have
 * passed against every one of those broken implementations.
 */

import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { describe, test } from "node:test";

import { loadEnvFile } from "../util/env.ts";
import {
  signToken,
  TOKEN_LIFETIME_SECONDS,
  verifyToken,
  type IssuableClaims,
} from "./jwt.ts";

// A fixed secret for the tests. Long enough to clear the minimum-length check,
// and obviously not a real credential — it protects nothing and signs nothing
// that outlives the test process.
const TEST_SECRET = "test-only-signing-secret-not-used-anywhere-real";

// Priming the .env loader before overriding the variable matters. lib/auth/jwt.ts
// calls loadEnvFile() on each use, and that helper reads the file exactly once
// and never overwrites a variable that is already set. Forcing the read to
// happen here means the "no secret configured" test further down can delete the
// variable and be sure nothing re-populates it from a developer's real .env.
loadEnvFile();
process.env.CLOUDSENTINEL_JWT_SECRET = TEST_SECRET;

/** The claims used by most tests. */
const CLAIMS: IssuableClaims = {
  sub: "42",
  email: "kevin@example.com",
  role: "viewer",
  tv: 1,
};

// ---------------------------------------------------------------------------
// Helpers for building hand-crafted, and deliberately malicious, tokens
// ---------------------------------------------------------------------------

function b64url(value: object | string): string {
  return Buffer.from(
    typeof value === "string" ? value : JSON.stringify(value),
  ).toString("base64url");
}

/**
 * Builds a token signed with the *correct* secret.
 *
 * Used for the attacks that are not about breaking the signature — algorithm
 * confusion, malformed claims, a future `iat`. Those must be rejected even
 * though the HMAC itself is genuine, which is the interesting case: a verifier
 * that stops at "the signature checks out" lets all of them through.
 */
function forgeSigned(header: object, payload: object): string {
  const input = `${b64url(header)}.${b64url(payload)}`;
  const signature = createHmac("sha256", Buffer.from(TEST_SECRET, "utf8"))
    .update(input)
    .digest("base64url");
  return `${input}.${signature}`;
}

/** Decodes a token's payload without verifying it — exactly what an attacker can do. */
function peek(token: string): Record<string, unknown> {
  return JSON.parse(
    Buffer.from(token.split(".")[1]!, "base64url").toString("utf8"),
  );
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

// ---------------------------------------------------------------------------

describe("signToken", () => {
  test("produces three base64url parts", () => {
    const parts = signToken(CLAIMS).split(".");

    assert.equal(parts.length, 3);
    for (const part of parts) {
      assert.match(part, /^[A-Za-z0-9_-]+$/, "parts must be base64url");
    }
  });

  test("always sets an expiry", () => {
    // The most common way a JWT deployment goes wrong is a token that never
    // expires, which turns a single theft into permanent access. `exp` is set
    // inside signToken rather than accepted from the caller so that no code
    // path can omit it.
    const claims = peek(signToken(CLAIMS));

    assert.equal(typeof claims.exp, "number");
    assert.ok((claims.exp as number) > nowSeconds());
    assert.ok((claims.exp as number) <= nowSeconds() + TOKEN_LIFETIME_SECONDS + 1);
  });

  test("the payload is readable by anyone", () => {
    // Asserted explicitly so the property is impossible to forget: a JWT
    // payload is encoded, not encrypted. Nothing secret may ever go in one.
    const claims = peek(signToken(CLAIMS));

    assert.equal(claims.email, "kevin@example.com");
    assert.equal(claims.role, "viewer");
  });
});

describe("verifyToken — the happy path", () => {
  test("round-trips a token it just signed", () => {
    const result = verifyToken(signToken(CLAIMS));

    assert.ok(result.valid);
    assert.equal(result.claims.sub, "42");
    assert.equal(result.claims.email, "kevin@example.com");
    assert.equal(result.claims.role, "viewer");
    assert.equal(result.claims.tv, 1);
  });
});

describe("verifyToken — forgery", () => {
  test("rejects a token whose payload was edited", () => {
    // The core promise of the whole scheme: a client holding a viewer token
    // cannot promote itself to admin, because it cannot recompute the
    // signature without the secret.
    const token = signToken(CLAIMS);
    const [header, , signature] = token.split(".") as [string, string, string];
    const escalated = b64url({ ...peek(token), role: "admin" });

    const result = verifyToken(`${header}.${escalated}.${signature}`);

    assert.ok(!result.valid);
    assert.equal(result.reason, "bad_signature");
  });

  test("rejects the alg:none attack", () => {
    // The classic. The attacker rewrites the payload, declares the token
    // unsigned, and drops the signature. A verifier that reads the algorithm
    // out of the header and obeys it accepts this — several widely-used
    // libraries did, in 2015.
    const header = b64url({ alg: "none", typ: "JWT" });
    const payload = b64url({
      ...CLAIMS,
      role: "admin",
      iat: nowSeconds(),
      exp: nowSeconds() + 3600,
    });

    for (const token of [
      `${header}.${payload}.`, // empty signature
      `${header}.${payload}`, // signature omitted entirely
    ]) {
      assert.ok(!verifyToken(token).valid, "alg:none must never verify");
    }
  });

  test("rejects an algorithm swap even when the signature is genuine", () => {
    // Algorithm confusion. This token IS correctly HMAC-signed with the real
    // secret, so the signature check passes — but the header declares RS256.
    // It is still rejected, because this implementation decides the algorithm
    // itself and compares the header against that decision rather than
    // trusting what the token asks for.
    const token = forgeSigned(
      { alg: "RS256", typ: "JWT" },
      { ...CLAIMS, iat: nowSeconds(), exp: nowSeconds() + 3600 },
    );

    const result = verifyToken(token);

    assert.ok(!result.valid);
    assert.equal(result.reason, "unsupported_algorithm");
  });

  test("rejects a token signed with a different secret", () => {
    const input = `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({
      ...CLAIMS,
      iat: nowSeconds(),
      exp: nowSeconds() + 3600,
    })}`;
    const wrong = createHmac("sha256", "some-other-secret-entirely")
      .update(input)
      .digest("base64url");

    const result = verifyToken(`${input}.${wrong}`);

    assert.ok(!result.valid);
    assert.equal(result.reason, "bad_signature");
  });

  test("rejects structurally broken input without throwing", () => {
    // Every one of these arrives from the network. None may crash the request.
    for (const token of [
      "",
      "..",
      "one-part",
      "two.parts",
      "a.b.c.d",
      "!!!.???.***",
      `${b64url({ alg: "HS256" })}.not-valid-base64!.sig`,
    ]) {
      assert.ok(
        !verifyToken(token).valid,
        `expected rejection for ${JSON.stringify(token)}`,
      );
    }
  });

  test("rejects a validly-signed token carrying nonsense claims", () => {
    // Signed with the real secret, so the signature is genuine — but the claims
    // are the wrong shape. Verification must still refuse, because downstream
    // code reads these fields directly and a missing `sub` would otherwise
    // become a request authenticated as user `undefined`.
    const time = { iat: nowSeconds(), exp: nowSeconds() + 3600 };

    const bad: object[] = [
      { ...time, tv: 1, email: "x@y.z", role: "viewer" }, // no sub
      { ...time, tv: 1, sub: "", email: "x@y.z", role: "viewer" }, // empty sub
      { ...time, tv: 1, sub: "1", email: "x@y.z", role: "root" }, // unknown role
      { ...time, tv: 1, sub: "1", email: "x@y.z" }, // no role
      { ...time, sub: "1", email: "x@y.z", role: "admin" }, // no token version
      { sub: "1", email: "x@y.z", role: "admin", tv: 1 }, // no iat/exp
      { ...time, tv: 1, sub: 1, email: "x@y.z", role: "admin" }, // sub not a string
    ];

    for (const payload of bad) {
      const result = verifyToken(
        forgeSigned({ alg: "HS256", typ: "JWT" }, payload),
      );
      assert.ok(
        !result.valid,
        `expected rejection for ${JSON.stringify(payload)}`,
      );
    }
  });
});

describe("verifyToken — time", () => {
  test("rejects an expired token", () => {
    const result = verifyToken(signToken(CLAIMS, -1));

    assert.ok(!result.valid);
    assert.equal(result.reason, "expired");
  });

  test("rejects a token issued in the future", () => {
    // Not something a correct client produces, so it is worth distinguishing
    // from an ordinary expiry in the server log.
    const future = nowSeconds() + 3600;
    const token = forgeSigned(
      { alg: "HS256", typ: "JWT" },
      { ...CLAIMS, iat: future, exp: future + 3600 },
    );

    const result = verifyToken(token);

    assert.ok(!result.valid);
    assert.equal(result.reason, "issued_in_future");
  });

  test("tolerates small clock skew", () => {
    const slightlyAhead = nowSeconds() + 30;
    const token = forgeSigned(
      { alg: "HS256", typ: "JWT" },
      { ...CLAIMS, iat: slightlyAhead, exp: slightlyAhead + 3600 },
    );

    assert.ok(verifyToken(token).valid);
  });
});

describe("the signing secret", () => {
  test("refuses to sign with no secret configured", () => {
    // There is deliberately no development fallback. A default committed to
    // this repository would let anyone who read the source mint admin tokens
    // against any deployment that forgot to override it — and those are
    // precisely the deployments nobody is watching.
    delete process.env.CLOUDSENTINEL_JWT_SECRET;
    try {
      assert.throws(
        () => signToken(CLAIMS),
        /CLOUDSENTINEL_JWT_SECRET is not set/,
      );
    } finally {
      process.env.CLOUDSENTINEL_JWT_SECRET = TEST_SECRET;
    }
  });

  test("refuses a short secret", () => {
    process.env.CLOUDSENTINEL_JWT_SECRET = "short";
    try {
      assert.throws(() => signToken(CLAIMS), /too short/);
    } finally {
      process.env.CLOUDSENTINEL_JWT_SECRET = TEST_SECRET;
    }
  });
});
