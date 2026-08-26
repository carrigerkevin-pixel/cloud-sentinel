/**
 * CloudSentinel — integration tests for the account layer.
 *
 * Run with `npm run test:db`. **Requires a running PostgreSQL server**, which
 * is why this lives in a `.dbtest.ts` file: `npm test` must stay runnable with
 * no Docker, no database, and no credentials.
 *
 * What these cover that lib/auth/*.test.ts cannot. Those suites test the crypto
 * in isolation — a hash round-trips, a forged token is refused. None of that
 * says anything about the parts that only exist once a database is involved:
 * the `email = lower(email)` constraint, the unique-violation translation, and
 * above all the three revocation paths, where the security property is
 * precisely that a *previously valid* token stops being honoured after a row
 * changes. A pure unit test cannot express that, because there is no row.
 *
 * ## Isolation
 *
 * Every run creates a dedicated database and drops it at the end, so the
 * development database — and the scan history in it, the one thing in this
 * project that cannot be regenerated — is never touched.
 *
 * The database name deliberately differs from the one lib/db/scans.dbtest.ts
 * uses. `node --test` runs test *files* concurrently, so two files that created
 * and dropped the same database would race: one file's `DROP DATABASE` would
 * tear the other's schema out from under it, producing failures that look like
 * logic bugs and that only appear on machines with enough cores to run both at
 * once.
 */

import assert from "node:assert/strict";
import { randomBytes, scryptSync } from "node:crypto";
import { after, before, beforeEach, describe, test } from "node:test";

import { Pool } from "pg";

import { signToken, verifyToken } from "../auth/jwt.ts";
import { loadEnvFile } from "../util/env.ts";
import { closePool, query } from "./client.ts";
import { runMigrations } from "./migrate.ts";
import {
  authenticate,
  countUsers,
  createUser,
  deleteUser,
  DuplicateUserError,
  findUserByEmail,
  findUserById,
  listUsers,
  MIN_PASSWORD_LENGTH,
  normaliseEmail,
  revokeSessions,
  setPassword,
  setRole,
  userForClaims,
} from "./users.ts";

/** Name of the throwaway database these tests create and drop. */
const TEST_DATABASE = "cloudsentinel_usertest";

const EMAIL = "kevin@example.com";
const PASSWORD = "a-long-enough-test-passphrase";

/** A signing secret for the tests. Protects nothing outside this process. */
process.env.CLOUDSENTINEL_JWT_SECRET =
  "dbtest-only-signing-secret-not-used-anywhere-real";

/** Opens a connection to the server's default database, for CREATE/DROP DATABASE. */
function adminPool(): Pool {
  return new Pool({
    host: process.env.POSTGRES_HOST ?? "127.0.0.1",
    port: Number(process.env.POSTGRES_PORT ?? 5432),
    user: process.env.POSTGRES_USER ?? "cloudsentinel",
    password: process.env.POSTGRES_PASSWORD,
    database: "postgres",
  });
}

/**
 * Builds a genuine scrypt hash of `password` at deliberately outdated cost
 * parameters (N=1024 rather than the current 16384).
 *
 * Used to stand in for an account created before the cost was raised. It has to
 * be a real, verifiable hash rather than a made-up string, because the property
 * under test is that such a password still *works* and is then upgraded — not
 * merely that a malformed hash is rejected.
 */
function weakHashOf(password: string): string {
  const salt = randomBytes(16);
  const digest = scryptSync(password, salt, 32, { N: 1024, r: 8, p: 1 });
  return `scrypt$1024$8$1$${salt.toString("base64")}$${digest.toString("base64")}`;
}

/** Creates a user and returns a freshly signed, currently-valid token for them. */
async function userWithToken(role: "admin" | "viewer" = "admin") {
  const user = await createUser(EMAIL, PASSWORD, role);
  const token = signToken({
    sub: String(user.id),
    email: user.email,
    role: user.role,
    tv: user.tokenVersion,
  });
  const result = verifyToken(token);
  assert.ok(result.valid, "the freshly signed token should verify");
  return { user, claims: result.claims };
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

before(async () => {
  loadEnvFile();

  const admin = adminPool();
  try {
    // Dropped first in case a previous run was interrupted before cleanup.
    await admin.query(`DROP DATABASE IF EXISTS ${TEST_DATABASE}`);
    await admin.query(`CREATE DATABASE ${TEST_DATABASE}`);
  } finally {
    await admin.end();
  }

  // Point the shared client at the test database, before anything calls
  // getPool() and builds a pool against the wrong target.
  process.env.POSTGRES_DB = TEST_DATABASE;
  process.env.DATABASE_URL = "";

  await runMigrations();
});

beforeEach(async () => {
  await query("TRUNCATE users RESTART IDENTITY CASCADE");
});

after(async () => {
  await closePool();

  const admin = adminPool();
  try {
    await admin.query(`DROP DATABASE IF EXISTS ${TEST_DATABASE}`);
  } finally {
    await admin.end();
  }
});

// ---------------------------------------------------------------------------
// Creating accounts
// ---------------------------------------------------------------------------

describe("createUser", () => {
  test("stores a user with safe defaults", async () => {
    const user = await createUser(EMAIL, PASSWORD);

    assert.equal(user.email, EMAIL);
    // The default is the least-privileged role, so forgetting the argument
    // cannot accidentally mint an administrator.
    assert.equal(user.role, "viewer");
    assert.equal(user.tokenVersion, 1);
    assert.equal(user.lastLoginAt, null);
    assert.equal(await countUsers(), 1);
  });

  test("never returns the password hash", async () => {
    // The hash must not travel into route handlers, log lines, or JSON
    // responses. Asserted structurally rather than by convention.
    const user = await createUser(EMAIL, PASSWORD);
    assert.ok(!("password_hash" in user));
    assert.ok(!JSON.stringify(user).includes("scrypt"));
  });

  test("stores the password hashed, not in any recoverable form", async () => {
    await createUser(EMAIL, PASSWORD);
    const [row] = await query<{ password_hash: string }>(
      "SELECT password_hash FROM users WHERE email = $1",
      [EMAIL],
    );

    assert.ok(row!.password_hash.startsWith("scrypt$"));
    assert.ok(!row!.password_hash.includes(PASSWORD));
  });

  test("normalises the email before storing it", async () => {
    const user = await createUser("  KEVIN@Example.COM  ", PASSWORD);

    assert.equal(user.email, EMAIL);
    // And the normalised form is what lookups find, so a differently-cased
    // login attempt reaches the same account rather than silently missing.
    assert.ok(await findUserByEmail("Kevin@EXAMPLE.com"));
  });

  test("rejects a duplicate email regardless of case", async () => {
    await createUser(EMAIL, PASSWORD);

    await assert.rejects(
      () => createUser("KEVIN@EXAMPLE.COM", PASSWORD),
      DuplicateUserError,
    );
    assert.equal(await countUsers(), 1);
  });

  test("rejects a short password", async () => {
    await assert.rejects(
      () => createUser(EMAIL, "x".repeat(MIN_PASSWORD_LENGTH - 1)),
      /at least/,
    );
    assert.equal(await countUsers(), 0);
  });

  test("rejects an empty email", async () => {
    await assert.rejects(() => createUser("   ", PASSWORD), /email address/);
  });
});

describe("listUsers", () => {
  test("returns accounts oldest first", async () => {
    await createUser("first@example.com", PASSWORD, "admin");
    await createUser("second@example.com", PASSWORD);

    assert.deepEqual(
      (await listUsers()).map((user) => user.email),
      ["first@example.com", "second@example.com"],
    );
  });
});

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

describe("authenticate", () => {
  test("accepts the right password", async () => {
    await createUser(EMAIL, PASSWORD, "admin");
    const user = await authenticate(EMAIL, PASSWORD);

    assert.equal(user?.email, EMAIL);
    assert.equal(user?.role, "admin");
  });

  test("accepts a differently-cased email", async () => {
    await createUser(EMAIL, PASSWORD);
    assert.ok(await authenticate("KEVIN@Example.com", PASSWORD));
  });

  test("rejects the wrong password", async () => {
    await createUser(EMAIL, PASSWORD);
    assert.equal(await authenticate(EMAIL, "not-the-right-passphrase"), null);
  });

  test("rejects an unknown account", async () => {
    assert.equal(await authenticate("nobody@example.com", PASSWORD), null);
  });

  test("costs the same for an unknown email as for a wrong password", async () => {
    // SECURITY: this is the user-enumeration defence, and it is the reason
    // lib/db/users.ts verifies against DECOY_PASSWORD_HASH when no row matches.
    // Without that, an unknown address would be answered in microseconds while
    // a known one paid the full scrypt cost, and the login form would become an
    // oracle telling an attacker which addresses hold accounts.
    //
    // The 3x bound is loose on purpose: the real ratio is very close to 1, and
    // a tight bound would flake on a loaded CI runner. Anything that removed
    // the decoy would show a ratio in the hundreds.
    await createUser(EMAIL, PASSWORD);

    const started = process.hrtime.bigint();
    await authenticate("nobody@example.com", PASSWORD);
    const unknown = Number(process.hrtime.bigint() - started);

    const startedKnown = process.hrtime.bigint();
    await authenticate(EMAIL, "not-the-right-passphrase");
    const known = Number(process.hrtime.bigint() - startedKnown);

    const ratio = Math.max(unknown, known) / Math.min(unknown, known);
    assert.ok(
      ratio < 3,
      `unknown-email login was ${ratio.toFixed(1)}x the cost of a known one; ` +
        "the decoy hash is probably not being used",
    );
  });

  test("records last_login_at only on success", async () => {
    const created = await createUser(EMAIL, PASSWORD);
    assert.equal(created.lastLoginAt, null);

    await authenticate(EMAIL, "wrong-password-here");
    assert.equal((await findUserById(created.id))?.lastLoginAt, null);

    await authenticate(EMAIL, PASSWORD);
    assert.ok((await findUserById(created.id))?.lastLoginAt instanceof Date);
  });

  test("upgrades a password hashed with weaker parameters", async () => {
    // Simulates an account created under older, cheaper settings: a genuine
    // scrypt hash of the real password, but at N=1024 instead of 16384. It must
    // still log in, and the stored hash must be rewritten at the current cost
    // afterwards — a successful login is the only moment the plaintext is
    // legitimately available to do that with.
    const user = await createUser(EMAIL, PASSWORD);
    await query("UPDATE users SET password_hash = $2 WHERE id = $1", [
      user.id,
      weakHashOf(PASSWORD),
    ]);

    assert.ok(
      await authenticate(EMAIL, PASSWORD),
      "a hash at older parameters must still authenticate",
    );

    const [row] = await query<{ password_hash: string }>(
      "SELECT password_hash FROM users WHERE id = $1",
      [user.id],
    );
    assert.ok(
      row!.password_hash.startsWith("scrypt$16384$"),
      "the hash should have been upgraded to the current cost",
    );

    // And the upgraded hash must still accept the same password — an upgrade
    // that locked the user out would be worse than no upgrade at all.
    assert.ok(await authenticate(EMAIL, PASSWORD));
  });

  test("fails cleanly when the stored hash is corrupt", async () => {
    // A damaged row must fail one login attempt, not throw out of the login
    // endpoint for everybody.
    const user = await createUser(EMAIL, PASSWORD);
    await query("UPDATE users SET password_hash = $2 WHERE id = $1", [
      user.id,
      "this-is-not-a-hash",
    ]);

    assert.equal(await authenticate(EMAIL, PASSWORD), null);
  });
});

// ---------------------------------------------------------------------------
// Revocation — the reason a stateless token is safe to use here
// ---------------------------------------------------------------------------

describe("userForClaims", () => {
  test("resolves a current token to its user", async () => {
    const { user, claims } = await userWithToken();
    assert.equal((await userForClaims(claims))?.id, user.id);
  });

  test("stops honouring a token after sessions are revoked", async () => {
    const { user, claims } = await userWithToken();
    assert.ok(await userForClaims(claims));

    await revokeSessions(user.id);

    // The token itself is still cryptographically valid and unexpired — the
    // signature check would pass. It is the token_version comparison that
    // refuses it, which is the whole point of storing that column.
    assert.ok(verifyToken(signToken(claims)).valid);
    assert.equal(await userForClaims(claims), null);
  });

  test("stops honouring an admin token after a demotion", async () => {
    const { user, claims } = await userWithToken("admin");
    await setRole(user.id, "viewer");

    // Without this check a demoted administrator would keep administrative
    // access until their token happened to expire, which would make the
    // demotion advisory rather than effective.
    assert.equal(await userForClaims(claims), null);
  });

  test("stops honouring a token after a password change", async () => {
    // A password is most often changed because it may have been exposed, and a
    // token already in an attacker's hands would otherwise keep working.
    const { user, claims } = await userWithToken();
    await setPassword(user.id, "an-entirely-different-passphrase");

    assert.equal(await userForClaims(claims), null);
  });

  test("stops honouring a token after the account is deleted", async () => {
    const { user, claims } = await userWithToken();
    await deleteUser(user.id);

    assert.equal(await userForClaims(claims), null);
  });

  test("rejects claims with a non-numeric subject", async () => {
    await userWithToken();
    assert.equal(
      await userForClaims({ sub: "not-a-number", role: "admin", tv: 1 }),
      null,
    );
  });
});

describe("setPassword", () => {
  test("changes the password and invalidates the old one", async () => {
    const user = await createUser(EMAIL, PASSWORD);
    await setPassword(user.id, "an-entirely-different-passphrase");

    assert.equal(await authenticate(EMAIL, PASSWORD), null);
    assert.ok(await authenticate(EMAIL, "an-entirely-different-passphrase"));
  });

  test("rejects a short password", async () => {
    const user = await createUser(EMAIL, PASSWORD);
    await assert.rejects(() => setPassword(user.id, "short"), /at least/);
    // And the original password still works, so a rejected change is a no-op.
    assert.ok(await authenticate(EMAIL, PASSWORD));
  });
});

describe("normaliseEmail", () => {
  test("lowercases and trims", () => {
    assert.equal(normaliseEmail("  Kevin@Example.COM "), EMAIL);
  });
});
