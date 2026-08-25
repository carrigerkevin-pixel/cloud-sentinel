/**
 * CloudSentinel — tests for the S3 compliance rules.
 *
 * Run with `npm test`. Uses Node's built-in test runner, so no test framework
 * dependency and no Docker, LocalStack, or credentials are needed.
 *
 * Each rule gets three kinds of test, and the second two are the ones that
 * matter:
 *
 *   1. It fires on the configuration it is meant to catch.
 *   2. It stays silent on the compliant configuration — a rule that flags a
 *      correctly-configured bucket teaches its reader to ignore the whole
 *      report, so the false-positive case is tested as deliberately as the
 *      true-positive one.
 *   3. It returns *inconclusive*, never a pass, when the setting it depends on
 *      appears in the resource's `unobserved` list. This is the contract from
 *      lib/types/resource.ts, and it is the single easiest thing to break by
 *      accident: reading a `null` config field as "the setting is off" turns a
 *      failed observation into a confident clean result, which is exactly the
 *      false negative this project is organised around avoiding.
 */

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import type {
  BucketAclGrant,
  S3BucketConfig,
  S3BucketResource,
} from "../types/resource.ts";
import {
  accessLoggingDisabledRule,
  blockPublicAccessRule,
  defaultEncryptionRule,
  publicBucketAclRule,
  publicBucketPolicyRule,
  versioningDisabledRule,
} from "./s3.ts";
import type { RuleVerdict } from "./types.ts";

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

/**
 * A fully compliant bucket, used as the starting point for every test.
 *
 * Building each case as "compliant, except for one thing" is what makes the
 * tests readable as security statements: the override in each test *is* the
 * misconfiguration being described.
 */
const COMPLIANT_CONFIG: S3BucketConfig = {
  createdAt: "2026-01-01T00:00:00.000Z",
  publicAccessBlock: {
    blockPublicAcls: true,
    ignorePublicAcls: true,
    blockPublicPolicy: true,
    restrictPublicBuckets: true,
  },
  policy: null,
  policyRaw: null,
  aclGrants: [
    {
      granteeType: "CanonicalUser",
      granteeId: "owner-canonical-id",
      granteeName: "owner",
      permission: "FULL_CONTROL",
    },
  ],
  versioning: "Enabled",
  loggingEnabled: true,
  loggingTargetBucket: "cloudsentinel-private-logs",
  encryptionAlgorithm: "AES256",
};

/** Builds an S3 bucket resource with the given config overrides. */
function bucket(
  overrides: Partial<S3BucketConfig> = {},
  unobserved: string[] = [],
): S3BucketResource {
  return {
    id: "arn:aws:s3:::test-bucket",
    type: "s3_bucket",
    name: "test-bucket",
    region: "us-east-1",
    tags: {},
    collectedAt: "2026-08-25T00:00:00.000Z",
    unobserved,
    config: { ...COMPLIANT_CONFIG, ...overrides },
  };
}

/** The public ACL grant AWS uses for "anyone on the internet". */
function allUsersGrant(
  permission: BucketAclGrant["permission"] = "READ",
): BucketAclGrant {
  return {
    granteeType: "Group",
    granteeId: "http://acs.amazonaws.com/groups/global/AllUsers",
    granteeName: null,
    permission,
  };
}

/** Asserts a rule returned exactly one passing verdict. */
function assertPasses(verdicts: RuleVerdict[]): void {
  assert.deepEqual(verdicts, [{ status: "pass" }]);
}

/** Returns the single verdict a rule produced, failing if there is not exactly one. */
function only(verdicts: RuleVerdict[]): RuleVerdict {
  assert.equal(verdicts.length, 1, `expected one verdict, got ${verdicts.length}`);
  return verdicts[0]!;
}

// ---------------------------------------------------------------------------
// Block Public Access
// ---------------------------------------------------------------------------

describe("s3-block-public-access", () => {
  test("passes when all four settings are enabled", () => {
    assertPasses(blockPublicAccessRule.evaluate(bucket()));
  });

  test("fails when all four settings are disabled", () => {
    const verdict = only(
      blockPublicAccessRule.evaluate(
        bucket({
          publicAccessBlock: {
            blockPublicAcls: false,
            ignorePublicAcls: false,
            blockPublicPolicy: false,
            restrictPublicBuckets: false,
          },
        }),
      ),
    );
    assert.equal(verdict.status, "fail");
    assert.equal(verdict.title, undefined, "should use the rule's default title");
  });

  test("fails when there is no configuration at all", () => {
    // AWS returns a 404 here, which is easy to mistake for a safe default. It
    // is the opposite: nothing is blocking a public ACL or policy.
    const verdict = only(
      blockPublicAccessRule.evaluate(bucket({ publicAccessBlock: null })),
    );
    assert.equal(verdict.status, "fail");
    assert.match(verdict.detail, /no public access block configuration/i);
  });

  test("reports partial protection under its own headline and severity", () => {
    const verdict = only(
      blockPublicAccessRule.evaluate(
        bucket({
          publicAccessBlock: {
            blockPublicAcls: true,
            ignorePublicAcls: true,
            blockPublicPolicy: false,
            restrictPublicBuckets: false,
          },
        }),
      ),
    );
    assert.equal(verdict.status, "fail");
    assert.equal(
      verdict.title,
      "S3 bucket has Block Public Access partially disabled",
    );
    assert.equal(verdict.severity, "high");
    // The specific flags are what make it fixable.
    assert.match(verdict.detail, /BlockPublicPolicy/);
    assert.match(verdict.detail, /RestrictPublicBuckets/);
  });

  test("is inconclusive, not passing, when the setting was not observed", () => {
    const verdict = only(
      blockPublicAccessRule.evaluate(
        bucket({ publicAccessBlock: null }, ["publicAccessBlock"]),
      ),
    );
    assert.equal(verdict.status, "inconclusive");
  });
});

// ---------------------------------------------------------------------------
// Public bucket policy
// ---------------------------------------------------------------------------

describe("s3-public-bucket-policy", () => {
  test("passes when the bucket has no policy", () => {
    assertPasses(publicBucketPolicyRule.evaluate(bucket({ policy: null })));
  });

  test("fails on an anonymous s3:GetObject grant", () => {
    const verdict = only(
      publicBucketPolicyRule.evaluate(
        bucket({
          policy: {
            Version: "2012-10-17",
            Statement: [
              {
                Sid: "PublicReadGetObject",
                Effect: "Allow",
                Principal: "*",
                Action: "s3:GetObject",
                Resource: "arn:aws:s3:::test-bucket/*",
              },
            ],
          },
        }),
      ),
    );
    assert.equal(verdict.status, "fail");
    assert.equal(
      verdict.title,
      "S3 bucket policy grants s3:GetObject to Principal '*'",
    );
    assert.equal(verdict.key, "PublicReadGetObject");
  });

  test("reports one finding per statement, not one per matched action", () => {
    // A single statement granting s3:* is one thing to fix. Emitting a finding
    // for every sensitive action it covers would quadruple the count without
    // adding any work.
    const verdicts = publicBucketPolicyRule.evaluate(
      bucket({
        policy: {
          Statement: [
            {
              Sid: "Everything",
              Effect: "Allow",
              Principal: "*",
              Action: "s3:*",
              Resource: "arn:aws:s3:::test-bucket/*",
            },
          ],
        },
      }),
    );
    assert.equal(verdicts.length, 1);
    // The headline names the most severe action the wildcard actually confers,
    // so the reader sees the capability rather than the syntax.
    assert.equal(
      verdicts[0]?.status === "fail" && verdicts[0].title,
      "S3 bucket policy grants s3:DeleteObject to Principal '*'",
    );
  });

  test("does not flag a grant to a named account", () => {
    assertPasses(
      publicBucketPolicyRule.evaluate(
        bucket({
          policy: {
            Statement: [
              {
                Effect: "Allow",
                Principal: { AWS: "arn:aws:iam::111122223333:root" },
                Action: "s3:GetObject",
                Resource: "arn:aws:s3:::test-bucket/*",
              },
            ],
          },
        }),
      ),
    );
  });

  test("does not flag a public grant guarded by a condition", () => {
    // A public statement restricted to a VPC endpoint or a source IP range is
    // a legitimate pattern; flagging it would be noise.
    assertPasses(
      publicBucketPolicyRule.evaluate(
        bucket({
          policy: {
            Statement: [
              {
                Effect: "Allow",
                Principal: "*",
                Action: "s3:GetObject",
                Resource: "arn:aws:s3:::test-bucket/*",
                Condition: {
                  StringEquals: { "aws:SourceVpce": "vpce-1234567890abcdef0" },
                },
              },
            ],
          },
        }),
      ),
    );
  });

  test("reports a NotPrincipal statement as inconclusive rather than guessing", () => {
    const verdict = only(
      publicBucketPolicyRule.evaluate(
        bucket({
          policy: {
            Statement: [
              {
                Sid: "Inverted",
                Effect: "Allow",
                NotPrincipal: { AWS: "arn:aws:iam::111122223333:root" },
                Action: "s3:GetObject",
                Resource: "arn:aws:s3:::test-bucket/*",
              },
            ],
          },
        }),
      ),
    );
    assert.equal(verdict.status, "inconclusive");
    assert.match(verdict.detail, /NotAction\/NotResource\/NotPrincipal/);
  });

  test("is inconclusive when the policy could not be read", () => {
    const verdict = only(
      publicBucketPolicyRule.evaluate(bucket({ policy: null }, ["policy"])),
    );
    assert.equal(verdict.status, "inconclusive");
  });
});

// ---------------------------------------------------------------------------
// Public bucket ACL
// ---------------------------------------------------------------------------

describe("s3-public-bucket-acl", () => {
  test("passes on an owner-only ACL", () => {
    assertPasses(publicBucketAclRule.evaluate(bucket()));
  });

  test("fails on a READ grant to AllUsers", () => {
    const verdict = only(
      publicBucketAclRule.evaluate(
        bucket({ aclGrants: [...COMPLIANT_CONFIG.aclGrants, allUsersGrant()] }),
      ),
    );
    assert.equal(verdict.status, "fail");
    assert.equal(verdict.title, "S3 bucket ACL grants READ to AllUsers");
    assert.equal(verdict.key, "AllUsers:READ");
    assert.match(verdict.detail, /anonymous read access/i);
  });

  test("treats AuthenticatedUsers as public too", () => {
    // "AuthenticatedUsers" means any AWS account holder anywhere, which anyone
    // can become in minutes. Reading it as restrictive is a common and
    // expensive mistake.
    const verdict = only(
      publicBucketAclRule.evaluate(
        bucket({
          aclGrants: [
            {
              granteeType: "Group",
              granteeId:
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
              granteeName: null,
              permission: "READ",
            },
          ],
        }),
      ),
    );
    assert.equal(verdict.status, "fail");
    assert.match(
      verdict.status === "fail" ? (verdict.title ?? "") : "",
      /AuthenticatedUsers/,
    );
  });

  test("describes write grants as modification, not read", () => {
    const verdict = only(
      publicBucketAclRule.evaluate(
        bucket({ aclGrants: [allUsersGrant("WRITE_ACP")] }),
      ),
    );
    assert.equal(verdict.status, "fail");
    assert.match(verdict.detail, /anonymous modification/i);
  });

  test("emits one finding per grant so each is closed explicitly", () => {
    const verdicts = publicBucketAclRule.evaluate(
      bucket({ aclGrants: [allUsersGrant("READ"), allUsersGrant("WRITE")] }),
    );
    assert.equal(verdicts.length, 2);
    assert.deepEqual(
      verdicts.map((verdict) => (verdict.status === "fail" ? verdict.key : null)),
      ["AllUsers:READ", "AllUsers:WRITE"],
    );
  });

  test("is inconclusive when the ACL could not be read", () => {
    const verdict = only(
      publicBucketAclRule.evaluate(bucket({ aclGrants: [] }, ["aclGrants"])),
    );
    assert.equal(verdict.status, "inconclusive");
  });
});

// ---------------------------------------------------------------------------
// Versioning
// ---------------------------------------------------------------------------

describe("s3-versioning-disabled", () => {
  test("passes when versioning is enabled", () => {
    assertPasses(versioningDisabledRule.evaluate(bucket()));
  });

  test("fails when versioning was never enabled", () => {
    const verdict = only(
      versioningDisabledRule.evaluate(bucket({ versioning: "Disabled" })),
    );
    assert.equal(verdict.status, "fail");
    assert.equal(verdict.title, undefined);
  });

  test("distinguishes suspended from never-enabled", () => {
    // Suspended means old versions may still exist and still cost money while
    // new writes are unprotected — a different situation, and a different fix.
    const verdict = only(
      versioningDisabledRule.evaluate(bucket({ versioning: "Suspended" })),
    );
    assert.equal(verdict.status, "fail");
    assert.equal(verdict.title, "S3 bucket has versioning suspended");
  });

  test("is inconclusive when versioning could not be read", () => {
    const verdict = only(
      versioningDisabledRule.evaluate(
        bucket({ versioning: "Disabled" }, ["versioning"]),
      ),
    );
    assert.equal(verdict.status, "inconclusive");
  });
});

// ---------------------------------------------------------------------------
// Access logging
// ---------------------------------------------------------------------------

describe("s3-access-logging-disabled", () => {
  test("passes when logging is on", () => {
    assertPasses(accessLoggingDisabledRule.evaluate(bucket()));
  });

  test("fails when logging is off", () => {
    const verdict = only(
      accessLoggingDisabledRule.evaluate(
        bucket({ loggingEnabled: false, loggingTargetBucket: null }),
      ),
    );
    assert.equal(verdict.status, "fail");
  });

  test("is inconclusive when logging state could not be read", () => {
    const verdict = only(
      accessLoggingDisabledRule.evaluate(
        bucket({ loggingEnabled: false }, ["loggingEnabled"]),
      ),
    );
    assert.equal(verdict.status, "inconclusive");
  });
});

// ---------------------------------------------------------------------------
// Default encryption
// ---------------------------------------------------------------------------

describe("s3-default-encryption-disabled", () => {
  test("passes when a default algorithm is configured", () => {
    assertPasses(defaultEncryptionRule.evaluate(bucket()));
  });

  test("fails when there is no default encryption rule", () => {
    const verdict = only(
      defaultEncryptionRule.evaluate(bucket({ encryptionAlgorithm: null })),
    );
    assert.equal(verdict.status, "fail");
  });

  test("is inconclusive when encryption could not be read", () => {
    const verdict = only(
      defaultEncryptionRule.evaluate(
        bucket({ encryptionAlgorithm: null }, ["encryptionAlgorithm"]),
      ),
    );
    assert.equal(verdict.status, "inconclusive");
  });
});
