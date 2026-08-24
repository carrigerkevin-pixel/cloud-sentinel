/**
 * CloudSentinel — tests for the S3 collector.
 *
 * Run with `npm test`. Uses Node's built-in test runner (`node:test`) and
 * assertion library, so the project needs no test framework dependency and the
 * suite runs anywhere Node runs — including a GitHub Actions job with no
 * Docker, no LocalStack, and no AWS credentials.
 *
 * Two kinds of test live here:
 *
 * 1. Pure-function tests for the parsing helpers, which is where AWS's odder
 *    data shapes get handled.
 * 2. Behavioural tests that drive `collectS3Buckets` with a fake S3 client.
 *    These pin down the distinction between "the setting is off" and "we could
 *    not read the setting" — the bug that made the collector report gaps in
 *    LocalStack's emulation as though they were real findings. It is exactly
 *    the kind of defect that reappears the moment someone adds a new error code
 *    to a tolerated list without thinking, so it is worth a test that fails
 *    loudly.
 */

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import type { S3Client } from "@aws-sdk/client-s3";

import {
  collectS3Buckets,
  normalizeAclGrants,
  parsePolicyDocument,
} from "./s3.ts";

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/** Builds an error shaped like the ones the AWS SDK throws. */
function awsError(code: string, message = code): Error {
  return Object.assign(new Error(message), { name: code });
}

/**
 * Handlers keyed by AWS SDK command class name, e.g. `"GetBucketPolicyCommand"`.
 * A handler either returns the response or throws to simulate an API error.
 */
type Handlers = Record<string, () => unknown>;

/**
 * A minimal stand-in for `S3Client` that dispatches on the command's class
 * name.
 *
 * The real client is never constructed, so these tests touch no network and
 * cannot accidentally reach a live endpoint. This is why `collectS3Buckets`
 * accepts an optional client argument — dependency injection purely so the
 * collection logic can be exercised in isolation.
 */
function fakeS3(handlers: Handlers): S3Client {
  return {
    send: async (command: object) => {
      const name = command.constructor.name;
      const handler = handlers[name];
      if (!handler) {
        throw new Error(`test fake has no handler for ${name}`);
      }
      return handler();
    },
  } as unknown as S3Client;
}

/**
 * A bucket where every setting reads successfully and the unconfigured ones
 * report their normal "absent" errors. Individual tests override one entry to
 * isolate the behaviour under test.
 */
function baseHandlers(): Handlers {
  return {
    ListBucketsCommand: () => ({
      Buckets: [{ Name: "test-bucket", CreationDate: new Date("2026-01-01") }],
    }),
    GetPublicAccessBlockCommand: () => ({
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true,
        IgnorePublicAcls: true,
        BlockPublicPolicy: true,
        RestrictPublicBuckets: true,
      },
    }),
    // Genuinely absent: this bucket has no policy, which is a normal state.
    GetBucketPolicyCommand: () => {
      throw awsError("NoSuchBucketPolicy");
    },
    GetBucketAclCommand: () => ({ Grants: [] }),
    GetBucketVersioningCommand: () => ({ Status: "Enabled" }),
    GetBucketLoggingCommand: () => ({}),
    GetBucketEncryptionCommand: () => {
      throw awsError("ServerSideEncryptionConfigurationNotFoundError");
    },
    GetBucketTaggingCommand: () => {
      throw awsError("NoSuchTagSet");
    },
    GetBucketLocationCommand: () => ({}),
  };
}

// ---------------------------------------------------------------------------
// Policy parsing
// ---------------------------------------------------------------------------

describe("parsePolicyDocument", () => {
  test("parses a policy whose Statement is an array", () => {
    const parsed = parsePolicyDocument(
      JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          { Effect: "Allow", Action: "s3:GetObject", Resource: "*" },
          { Effect: "Deny", Action: "s3:DeleteObject", Resource: "*" },
        ],
      }),
    );

    assert.equal(parsed?.Statement.length, 2);
    assert.equal(parsed?.Version, "2012-10-17");
  });

  test("normalizes a single-object Statement into an array", () => {
    // AWS's policy grammar allows a bare object here, and a hand-written
    // "make this bucket public" policy is usually written that way. A rule
    // engine assuming an array would throw on precisely the policies that
    // matter most.
    const parsed = parsePolicyDocument(
      JSON.stringify({
        Version: "2012-10-17",
        Statement: {
          Effect: "Allow",
          Principal: "*",
          Action: "s3:GetObject",
          Resource: "arn:aws:s3:::public/*",
        },
      }),
    );

    assert.ok(Array.isArray(parsed?.Statement));
    assert.equal(parsed?.Statement.length, 1);
    assert.equal(parsed?.Statement[0]?.Principal, "*");
  });

  test("returns null for malformed JSON rather than throwing", () => {
    // The raw text is kept on the resource as `policyRaw`, so a parse failure
    // stays diagnosable instead of aborting the scan of every other bucket.
    assert.equal(parsePolicyDocument("{not json"), null);
  });

  test("returns null when the document has no Statement", () => {
    assert.equal(parsePolicyDocument(JSON.stringify({ Version: "2012-10-17" })), null);
  });
});

// ---------------------------------------------------------------------------
// ACL normalization
// ---------------------------------------------------------------------------

describe("normalizeAclGrants", () => {
  test("preserves the AllUsers group URI so a rule can match on it", () => {
    const grants = normalizeAclGrants([
      {
        Grantee: {
          Type: "Group",
          URI: "http://acs.amazonaws.com/groups/global/AllUsers",
        },
        Permission: "READ",
      },
    ]);

    assert.equal(grants.length, 1);
    assert.equal(grants[0]?.granteeType, "Group");
    assert.equal(
      grants[0]?.granteeId,
      "http://acs.amazonaws.com/groups/global/AllUsers",
    );
    assert.equal(grants[0]?.permission, "READ");
  });

  test("classifies an unrecognized grantee type as Unknown", () => {
    const grants = normalizeAclGrants([
      { Grantee: { Type: "SomethingNew", ID: "abc" }, Permission: "READ" },
    ]);

    assert.equal(grants[0]?.granteeType, "Unknown");
    assert.equal(grants[0]?.granteeId, "abc");
  });
});

// ---------------------------------------------------------------------------
// Absent vs. unobserved
// ---------------------------------------------------------------------------

describe("collectS3Buckets — absent vs. unobserved", () => {
  test("a genuinely absent setting is null and is not marked unobserved", async () => {
    const result = await collectS3Buckets(
      "2026-01-01T00:00:00.000Z",
      fakeS3(baseHandlers()),
    );

    const bucket = result.resources[0];
    assert.equal(result.resources.length, 1);
    assert.equal(bucket?.config.policy, null);
    assert.equal(bucket?.config.encryptionAlgorithm, null);

    // Nothing failed: AWS answered every question, and two of the answers were
    // "not configured". A rule may safely conclude from these nulls.
    assert.deepEqual(bucket?.unobserved, []);
    assert.deepEqual(result.errors, []);
  });

  test("an unreadable setting is marked unobserved and recorded as an error", async () => {
    // NotImplemented means the endpoint does not emulate this API. An earlier
    // version of the collector tolerated this code as though it meant "no
    // encryption configured", manufacturing a finding out of a gap in
    // LocalStack. It must now surface as a failure to observe.
    const handlers = baseHandlers();
    handlers.GetBucketEncryptionCommand = () => {
      throw awsError("NotImplemented", "not supported by this endpoint");
    };

    const result = await collectS3Buckets(
      "2026-01-01T00:00:00.000Z",
      fakeS3(handlers),
    );

    const bucket = result.resources[0];
    assert.equal(bucket?.config.encryptionAlgorithm, null);
    assert.ok(bucket?.unobserved.includes("encryptionAlgorithm"));

    assert.equal(result.errors.length, 1);
    assert.equal(result.errors[0]?.operation, "GetBucketEncryption");
    assert.equal(result.errors[0]?.resourceName, "test-bucket");
    assert.equal(result.errors[0]?.resourceType, "s3_bucket");
  });

  test("a failure on one setting does not lose the rest of the bucket", async () => {
    const handlers = baseHandlers();
    handlers.GetPublicAccessBlockCommand = () => {
      throw awsError("AccessDenied", "not authorized");
    };

    const result = await collectS3Buckets(
      "2026-01-01T00:00:00.000Z",
      fakeS3(handlers),
    );

    const bucket = result.resources[0];
    assert.ok(bucket?.unobserved.includes("publicAccessBlock"));
    // Everything else was still collected — a partial read is more useful than
    // a dropped resource, as long as the gap is declared.
    assert.equal(bucket?.config.versioning, "Enabled");
    assert.equal(bucket?.name, "test-bucket");
  });
});

// ---------------------------------------------------------------------------
// Top-level failure
// ---------------------------------------------------------------------------

describe("collectS3Buckets — list failure", () => {
  test("records a service-level error and returns no resources", async () => {
    const handlers = baseHandlers();
    handlers.ListBucketsCommand = () => {
      throw awsError("AccessDenied", "not authorized");
    };

    const result = await collectS3Buckets(
      "2026-01-01T00:00:00.000Z",
      fakeS3(handlers),
    );

    assert.deepEqual(result.resources, []);
    assert.equal(result.errors.length, 1);
    assert.equal(result.errors[0]?.operation, "ListBuckets");
    // No named resource: the failure was learning what exists at all, so it
    // cannot be attributed to any particular bucket.
    assert.equal(result.errors[0]?.resourceName, null);
  });

  test("does not throw when the whole service is unreachable", async () => {
    // The caller decides what a failed scan means. Throwing here would abort
    // the EC2 and IAM collectors running alongside this one.
    await assert.doesNotReject(() =>
      collectS3Buckets(
        "2026-01-01T00:00:00.000Z",
        fakeS3({
          ListBucketsCommand: () => {
            throw awsError("NetworkingError", "connect ECONNREFUSED");
          },
        }),
      ),
    );
  });
});
