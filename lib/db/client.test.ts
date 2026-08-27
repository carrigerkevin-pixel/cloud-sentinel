/**
 * CloudSentinel — tests for the database connection's transport security.
 *
 * Run with `npm test`. Needs no database: {@link resolveSslOptions} is a pure
 * decision about *how* to connect, deliberately separated from the pool so it
 * can be tested without one — the same reasoning that keeps lib/db/lifecycle.ts
 * free of SQL.
 *
 * Where this sits in the architecture: it guards one rule in lib/db/client.ts —
 * loopback connects in the clear, everything else verifies a certificate. That
 * rule is the only thing standing between scan findings and a network, and
 * findings are a ranked list of where an environment is weakest, so a bug here
 * leaks a target map rather than merely breaking a feature.
 *
 * The tests are weighted accordingly. Most of what follows is not "does the
 * happy path work" but "can verification be turned off by any route" — because
 * the failure that matters is silent. A connection with `rejectUnauthorized`
 * accidentally false still connects, still returns rows, and looks identical in
 * every log; nothing about the running system would appear wrong.
 */

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, test } from "node:test";

import { resolveSslOptions, type DatabaseConfig } from "./client.ts";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** The environment variable under test, spelled once. */
const CA_FILE = "POSTGRES_CA_CERT_FILE";

/**
 * Builds a resolved config. Only `isLocal` is consulted by the code under test;
 * the other fields exist to satisfy the type and to make failures readable.
 */
function config(overrides: Partial<DatabaseConfig> = {}): DatabaseConfig {
  return {
    host: "cloudsentinel-db",
    port: 5432,
    database: "cloudsentinel",
    user: "cloudsentinel",
    isLocal: false,
    ...overrides,
  };
}

/**
 * Writes a throwaway PEM file and returns its path.
 *
 * The contents are not a real certificate and do not need to be: this function
 * only reads the file, and never parses it — `pg` hands the bytes to Node's TLS
 * stack, which is where a malformed certificate would be rejected. Testing
 * against a real certificate here would be testing OpenSSL.
 */
const tempDirs: string[] = [];
function writePem(contents = "-----BEGIN CERTIFICATE-----\nnot-a-real-cert\n-----END CERTIFICATE-----\n"): string {
  const dir = mkdtempSync(join(tmpdir(), "cloudsentinel-ca-"));
  tempDirs.push(dir);
  const path = join(dir, "ca.pem");
  writeFileSync(path, contents, "utf8");
  return path;
}

afterEach(() => {
  delete process.env[CA_FILE];
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Loopback
// ---------------------------------------------------------------------------

describe("resolveSslOptions — loopback", () => {
  test("connects without TLS", () => {
    assert.equal(resolveSslOptions(config({ isLocal: true })), undefined);
  });

  test("ignores a CA file rather than half-enabling TLS", () => {
    // A leftover POSTGRES_CA_CERT_FILE in a shell must not quietly switch a
    // local connection to TLS: the Compose database has no certificate, so the
    // result would be a confusing handshake failure against a database that was
    // working a moment ago.
    process.env[CA_FILE] = writePem();
    assert.equal(resolveSslOptions(config({ isLocal: true })), undefined);
  });
});

// ---------------------------------------------------------------------------
// Remote — the cases that matter
// ---------------------------------------------------------------------------

describe("resolveSslOptions — remote", () => {
  test("verifies the certificate when no CA is configured", () => {
    const ssl = resolveSslOptions(config());
    assert.equal(ssl?.rejectUnauthorized, true);
    // No `ca`, so Node falls back to the system trust store — correct for a
    // managed database with a publicly-trusted certificate.
    assert.equal(ssl?.ca, undefined);
  });

  test("supplies the private CA and still verifies", () => {
    const pem = "-----BEGIN CERTIFICATE-----\nin-cluster-ca\n-----END CERTIFICATE-----\n";
    process.env[CA_FILE] = writePem(pem);

    const ssl = resolveSslOptions(config());
    assert.equal(ssl?.ca, pem);
    // The point of the whole feature: adding a private CA must *satisfy*
    // verification, never replace it.
    assert.equal(ssl?.rejectUnauthorized, true);
  });

  test("never disables verification, whatever the CA file contains", () => {
    // An empty or junk CA file is a plausible mistake — an unmounted secret
    // leaves a zero-byte file rather than an absent one. The connection must
    // still refuse an unverified certificate; failing the handshake is the
    // correct outcome, connecting insecurely is not.
    for (const contents of ["", "   ", "not a certificate at all"]) {
      process.env[CA_FILE] = writePem(contents);
      assert.equal(resolveSslOptions(config())?.rejectUnauthorized, true);
    }
  });

  test("refuses to start when the CA file is missing", () => {
    // The deployment said "pin this authority" and the file is not there. The
    // dangerous behaviour would be to shrug and fall back to the public trust
    // store, which silently widens what the client accepts from one private CA
    // to every authority on the internet. An unmounted Kubernetes Secret must
    // stop the pod, not downgrade it.
    process.env[CA_FILE] = join(tmpdir(), "cloudsentinel-does-not-exist", "ca.pem");

    assert.throws(
      () => resolveSslOptions(config()),
      (error: Error) => {
        assert.match(error.message, /POSTGRES_CA_CERT_FILE/);
        // The path is configuration and safe to print; assert it is there so a
        // future edit does not reduce this to an unactionable message.
        assert.match(error.message, /ca\.pem/);
        return true;
      },
    );
  });
});
