/**
 * CloudSentinel — tests for the IAM collector's parsing helpers.
 *
 * Run with `npm test`. No network, no LocalStack.
 *
 * The focus is the URL-encoding quirk. IAM returns policy documents
 * percent-encoded while S3 returns bucket policies as raw JSON, and forgetting
 * that produces a `JSON.parse` failure whose error message ("Unexpected token
 * %") gives no hint about the real cause. The collector tries both forms rather
 * than hard-coding which API does what; these tests hold that behaviour in
 * place from both directions.
 */

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { ageInDays, parsePolicyDocument } from "./iam.ts";

describe("parsePolicyDocument", () => {
  const document = {
    Version: "2012-10-17",
    Statement: [{ Sid: "AllowEverything", Effect: "Allow", Action: "*", Resource: "*" }],
  };

  test("parses a URL-encoded document, as GetPolicyVersion returns it", () => {
    const encoded = encodeURIComponent(JSON.stringify(document));

    const parsed = parsePolicyDocument(encoded);

    assert.equal(parsed?.Statement.length, 1);
    assert.equal(parsed?.Statement[0]?.Action, "*");
    assert.equal(parsed?.Statement[0]?.Resource, "*");
  });

  test("parses a plain JSON document, as LocalStack may return it", () => {
    // The fallback goes both ways deliberately: the emulator does not always
    // encode, and the collector should not care which behaviour it meets.
    const parsed = parsePolicyDocument(JSON.stringify(document));

    assert.equal(parsed?.Statement.length, 1);
    assert.equal(parsed?.Statement[0]?.Sid, "AllowEverything");
  });

  test("normalizes a single-object Statement into an array", () => {
    const parsed = parsePolicyDocument(
      JSON.stringify({
        Version: "2012-10-17",
        Statement: { Effect: "Allow", Action: "iam:PassRole", Resource: "*" },
      }),
    );

    assert.ok(Array.isArray(parsed?.Statement));
    assert.equal(parsed?.Statement[0]?.Action, "iam:PassRole");
  });

  test("returns null rather than throwing on an unparseable document", () => {
    // Null means "not evaluated" — a rule must report inconclusive, not clean.
    assert.equal(parsePolicyDocument("%%%not-a-document%%%"), null);
  });
});

describe("ageInDays", () => {
  const now = new Date("2026-08-24T12:00:00.000Z");

  test("counts whole days since creation", () => {
    assert.equal(ageInDays(new Date("2026-08-14T12:00:00.000Z"), now), 10);
  });

  test("reports a key created moments ago as zero days, not null", () => {
    // Zero and null mean different things: zero is a real age, null is an
    // unknown one. A "keys older than N days" rule must not confuse them.
    assert.equal(ageInDays(new Date("2026-08-24T11:00:00.000Z"), now), 0);
  });

  test("returns null when AWS gave no creation date", () => {
    assert.equal(ageInDays(undefined, now), null);
  });
});
