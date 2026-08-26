/**
 * CloudSentinel — tests for password hashing.
 *
 * Run with `npm test`. Pure crypto, no database and no network.
 *
 * These tests are slower than the rest of the suite, and that is the feature
 * working: each `hashPassword` call deliberately burns about 100 ms and 16 MB
 * of memory. A change that made this file noticeably fast would mean the cost
 * parameters had been weakened, which is precisely the regression worth
 * catching — so the timing assertion below is written to fail loudly rather
 * than to be quietly deleted for being slow.
 */

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  DECOY_PASSWORD_HASH,
  hashPassword,
  needsRehash,
  verifyPassword,
} from "./password.ts";

describe("hashPassword", () => {
  test("produces a parseable scrypt record", async () => {
    const stored = await hashPassword("correct horse battery staple");
    const parts = stored.split("$");

    assert.equal(parts.length, 6);
    assert.equal(parts[0], "scrypt");
    assert.equal(parts[1], "16384");
    assert.equal(parts[2], "8");
    assert.equal(parts[3], "1");
    // Salt is 16 bytes and the derived key 32, base64-encoded.
    assert.equal(Buffer.from(parts[4]!, "base64").length, 16);
    assert.equal(Buffer.from(parts[5]!, "base64").length, 32);
  });

  test("never stores the password itself", async () => {
    const password = "hunter2-is-a-terrible-password";
    const stored = await hashPassword(password);

    // The obvious mistake, asserted against directly: the whole point of the
    // file is that reading the database must not reveal the password.
    assert.ok(!stored.includes(password));
  });

  test("two users with the same password get different hashes", async () => {
    // This is the salt doing its job. Identical hashes would tell an attacker
    // which accounts share a password and would make one precomputed table
    // work against every row at once.
    const a = await hashPassword("same password");
    const b = await hashPassword("same password");

    assert.notEqual(a, b);
    // Both must still verify — different salts, same password.
    assert.ok(await verifyPassword("same password", a));
    assert.ok(await verifyPassword("same password", b));
  });

  test("refuses an empty password", async () => {
    await assert.rejects(() => hashPassword(""), /empty password/);
  });

  test("is deliberately slow", async () => {
    // Guards the cost parameters. If someone drops N to make the tests faster,
    // stored passwords become cheap to crack offline, and nothing else in the
    // suite would notice. 20 ms is a very loose floor — the real figure is
    // around 100 ms — chosen so this cannot flake on a fast machine while
    // still catching a drop to a trivial cost.
    const started = performance.now();
    await hashPassword("timing");
    assert.ok(
      performance.now() - started > 20,
      "hashing completed suspiciously fast; check the scrypt cost parameters",
    );
  });
});

describe("verifyPassword", () => {
  test("accepts the right password", async () => {
    const stored = await hashPassword("s3cure-enough");
    assert.equal(await verifyPassword("s3cure-enough", stored), true);
  });

  test("rejects the wrong password", async () => {
    const stored = await hashPassword("s3cure-enough");
    assert.equal(await verifyPassword("s3cure-enoug", stored), false);
    assert.equal(await verifyPassword("S3cure-enough", stored), false);
    assert.equal(await verifyPassword("", stored), false);
  });

  test("rejects rather than throws on a malformed stored hash", async () => {
    // A corrupt row must fail one login, not crash the login endpoint for
    // everyone. Every one of these must come back false, never true and never
    // an exception.
    const malformed = [
      "",
      "not-a-hash",
      "scrypt$16384$8$1$onlyfiveparts",
      "bcrypt$16384$8$1$c2FsdA==$aGFzaA==",
      "scrypt$abc$8$1$c2FsdA==$aGFzaA==",
      "scrypt$16384$8$1$$aGFzaA==",
      "scrypt$16384$8$1$c2FsdA==$",
    ];

    for (const stored of malformed) {
      assert.equal(
        await verifyPassword("anything", stored),
        false,
        `expected false for ${JSON.stringify(stored)}`,
      );
    }
  });

  test("refuses absurd cost parameters from the database", async () => {
    // SECURITY: the parameters are read out of the `users` table, so a row an
    // attacker managed to write could otherwise demand enormous amounts of
    // memory — a denial of service triggered by an ordinary login attempt.
    // These must be rejected quickly rather than attempted.
    const started = performance.now();
    assert.equal(
      await verifyPassword("x", "scrypt$1073741824$64$16$c2FsdA==$aGFzaA=="),
      false,
    );
    assert.ok(
      performance.now() - started < 50,
      "an out-of-range cost parameter should be rejected without running scrypt",
    );
  });
});

describe("DECOY_PASSWORD_HASH", () => {
  test("is well-formed but matches nothing", async () => {
    // It has to be *parseable*, or verification would short-circuit and the
    // login route would answer faster for unknown accounts than for real ones
    // — reintroducing the exact user-enumeration timing leak it exists to
    // close.
    const started = performance.now();
    assert.equal(await verifyPassword("password", DECOY_PASSWORD_HASH), false);
    assert.equal(await verifyPassword("", DECOY_PASSWORD_HASH), false);
    assert.ok(
      performance.now() - started > 20,
      "the decoy must cost the same as a real verification",
    );
  });
});

describe("needsRehash", () => {
  test("is false for a hash created with the current parameters", async () => {
    assert.equal(needsRehash(await hashPassword("current")), false);
  });

  test("is true for a weaker hash", () => {
    // N=1024 was created under older, cheaper settings. It still verifies, but
    // it should be upgraded at the next successful login.
    assert.equal(needsRehash("scrypt$1024$8$1$c2FsdA==$aGFzaA=="), true);
  });

  test("is true for an unparseable hash", () => {
    // Something is wrong with the row; rewriting it at the current parameters
    // is the correct repair.
    assert.equal(needsRehash("garbage"), true);
  });
});
