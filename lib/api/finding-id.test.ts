/**
 * CloudSentinel — tests for finding id encoding.
 *
 * Run with `npm test`. Pure string handling, no network and no database.
 *
 * The encoder exists because real finding ids contain forward slashes, so most
 * of what is worth testing is the awkward input: ids with slashes and pipes,
 * and tokens that are not valid base64url at all. A decoder that quietly
 * accepted junk would turn a malformed URL into a database lookup for an id
 * nobody could ever have issued.
 */

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { decodeFindingId, encodeFindingId } from "./finding-id.ts";

/** A real finding id, taken verbatim from the committed fixture's scan. */
const REAL_ID =
  "ec2-unrestricted-ingress|arn:aws:ec2:us-east-1:000000000000:security-group/sg-7262afbbf214cd66b|ipv4:tcp/22";

describe("encodeFindingId", () => {
  test("produces a URL-safe token", () => {
    const token = encodeFindingId(REAL_ID);

    // The whole point: nothing here needs escaping in a path segment. In
    // particular no "/" — the character that made the raw id unusable.
    assert.match(token, /^[A-Za-z0-9_-]+$/);
    assert.ok(!token.includes("/"));
    assert.ok(!token.includes("+"));
    assert.ok(!token.includes("="));
  });
});

describe("round trip", () => {
  test("recovers ids containing the awkward characters", () => {
    for (const id of [
      REAL_ID,
      "s3-block-public-access|arn:aws:s3:::cloudsentinel-public-data|",
      "iam-user-mfa|arn:aws:iam::000000000000:user/cloudsentinel-admin|",
      "a|b|c",
      "/",
      "|",
      "x",
      // Non-ASCII: a resource name can contain anything AWS permits in a tag.
      "rule|résumé-bucket|ipv6:tcp/22",
    ]) {
      assert.equal(
        decodeFindingId(encodeFindingId(id)),
        id,
        `failed to round-trip ${JSON.stringify(id)}`,
      );
    }
  });
});

describe("decodeFindingId", () => {
  test("rejects anything that is not valid base64url", () => {
    // Node's base64 decoder silently ignores characters outside the alphabet
    // rather than reporting them. Without the explicit validation these would
    // decode to *something*, and two different URLs could resolve to the same
    // finding.
    for (const token of [
      "",
      "not valid",
      "has/slash",
      "has+plus",
      "has=padding",
      "!!!",
      "abc$def",
    ]) {
      assert.equal(
        decodeFindingId(token),
        null,
        `expected rejection for ${JSON.stringify(token)}`,
      );
    }
  });

  test("rejects a token with characters appended", () => {
    // Caught a real bug when first written. Appending one base64url character
    // can decode to the original id plus a trailing NUL byte — and that longer
    // string re-encodes to the longer token perfectly happily, so the
    // round-trip check alone lets it through. The control-character check is
    // what rejects it.
    const token = encodeFindingId(REAL_ID);
    for (const suffix of ["A", "AA", "AAA", "AB"]) {
      assert.equal(
        decodeFindingId(token + suffix),
        null,
        `expected rejection for a token with "${suffix}" appended`,
      );
    }
  });

  test("rejects a token decoding to control characters", () => {
    // A finding id is a rule id, an ARN, and a port key — all printable. NUL in
    // particular must never reach a query: it terminates a string in C, so a
    // value carrying one can be read as two different strings by two different
    // layers.
    for (const id of ["a\u0000b", "rule|res\u001fource|key", "\u007f"]) {
      assert.equal(
        decodeFindingId(Buffer.from(id, "utf8").toString("base64url")),
        null,
        `expected rejection for ${JSON.stringify(id)}`,
      );
    }
  });

  test("rejects an over-long token without decoding it", () => {
    assert.equal(decodeFindingId("A".repeat(4096)), null);
  });
});
