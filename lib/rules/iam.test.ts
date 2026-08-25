/**
 * CloudSentinel — tests for the IAM compliance rules.
 *
 * Run with `npm test`. Uses Node's built-in test runner, so no test framework
 * dependency and no Docker, LocalStack, or credentials are needed.
 *
 * The most important test in this file is the one asserting that a user whose
 * only administrative access arrives through a group is still reported. That is
 * the false negative IAM auditing is most prone to: every field on the user
 * object says "harmless", and only resolving the group's policies reveals a
 * full account administrator. A scanner that misses it produces a green
 * dashboard nobody has any reason to question.
 *
 * The mirror-image tests matter almost as much. A service account with no
 * console password must not be nagged about MFA, and a user with a properly
 * scoped `iam:PassRole` must not be flagged — a rule that cries wolf on correct
 * configuration is one people learn to filter out, which costs more than the
 * check was worth.
 *
 * SECURITY: no test here constructs a secret access key, because the data model
 * has nowhere to put one. Access key *ids* appear in fixtures and in findings;
 * an id is a public identifier and is what the remediation command needs.
 */

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import type {
  AccessKeySummary,
  GroupMembership,
  IamUserConfig,
  IamUserResource,
  PolicyDocument,
} from "../types/resource.ts";
import {
  adminPolicyAttachedRule,
  adminViaGroupRule,
  consoleWithoutMfaRule,
  longLivedAccessKeyRule,
  unrestrictedPassRoleRule,
} from "./iam.ts";
import type { RuleVerdict } from "./types.ts";

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

/** The `Action: "*"` on `Resource: "*"` document, in its usual shape. */
const ADMIN_DOCUMENT: PolicyDocument = {
  Version: "2012-10-17",
  Statement: [
    { Sid: "AllowEverything", Effect: "Allow", Action: "*", Resource: "*" },
  ],
};

/** A correctly scoped read-only document, used for the false-positive cases. */
const SCOPED_DOCUMENT: PolicyDocument = {
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "ReadOneBucket",
      Effect: "Allow",
      Action: ["s3:GetObject", "s3:ListBucket"],
      Resource: ["arn:aws:s3:::logs", "arn:aws:s3:::logs/*"],
    },
  ],
};

/**
 * A compliant user: no policies, no keys, no console access, no groups.
 *
 * Every test starts here and adds exactly one problem, so the override in each
 * test is a plain statement of the misconfiguration being described.
 */
const COMPLIANT_CONFIG: IamUserConfig = {
  userName: "test-user",
  arn: "arn:aws:iam::000000000000:user/test-user",
  createdAt: "2026-01-01T00:00:00.000Z",
  passwordLastUsed: null,
  hasConsoleAccess: false,
  mfaDeviceIds: [],
  accessKeys: [],
  attachedPolicies: [],
  inlinePolicies: [],
  groups: [],
};

/** Builds an IAM user resource with the given config overrides. */
function user(
  overrides: Partial<IamUserConfig> = {},
  unobserved: string[] = [],
): IamUserResource {
  return {
    id: "arn:aws:iam::000000000000:user/test-user",
    type: "iam_user",
    name: "test-user",
    // IAM is global, so its resources are not forced into a region.
    region: "global",
    tags: {},
    collectedAt: "2026-08-25T00:00:00.000Z",
    unobserved,
    config: { ...COMPLIANT_CONFIG, ...overrides },
  };
}

/** Builds a group membership granting the given attached policy document. */
function groupWith(
  groupName: string,
  document: PolicyDocument | null,
  kind: "attached" | "inline" = "attached",
): GroupMembership {
  const policy = { policyName: "GroupPolicy", document };
  return {
    groupName,
    attachedPolicies:
      kind === "attached"
        ? [{ ...policy, policyArn: `arn:aws:iam::000000000000:policy/GroupPolicy` }]
        : [],
    inlinePolicies: kind === "inline" ? [policy] : [],
  };
}

/** Builds an access key summary. */
function accessKey(overrides: Partial<AccessKeySummary> = {}): AccessKeySummary {
  return {
    accessKeyId: "AKIAIOSFODNN7EXAMPLE",
    status: "Active",
    createdAt: "2026-08-01T00:00:00.000Z",
    ageInDays: 24,
    ...overrides,
  };
}

/** Titles of the failing verdicts, in order. */
function failTitles(verdicts: RuleVerdict[], fallback: string): string[] {
  return verdicts
    .filter((verdict) => verdict.status === "fail")
    .map((verdict) =>
      verdict.status === "fail" ? (verdict.title ?? fallback) : "",
    );
}

// ---------------------------------------------------------------------------
// Directly-granted administrative access
// ---------------------------------------------------------------------------

describe("iam-admin-policy-direct", () => {
  test("passes on a user with no policies", () => {
    assert.deepEqual(adminPolicyAttachedRule.evaluate(user()), [
      { status: "pass" },
    ]);
  });

  test("passes on a user with only a scoped policy", () => {
    assert.deepEqual(
      adminPolicyAttachedRule.evaluate(
        user({ inlinePolicies: [{ policyName: "ReadOnly", document: SCOPED_DOCUMENT }] }),
      ),
      [{ status: "pass" }],
    );
  });

  test("flags an attached wildcard policy", () => {
    const verdicts = adminPolicyAttachedRule.evaluate(
      user({
        attachedPolicies: [
          {
            policyName: "WildcardAccess",
            policyArn: "arn:aws:iam::000000000000:policy/WildcardAccess",
            document: ADMIN_DOCUMENT,
          },
        ],
      }),
    );
    assert.deepEqual(failTitles(verdicts, ""), [
      "IAM user has an attached policy with Action '*' on Resource '*'",
    ]);
  });

  test("flags an inline wildcard policy under its own headline", () => {
    // The distinction is not cosmetic: an attached policy is detached, an
    // inline one is deleted or rewritten in place.
    const verdicts = adminPolicyAttachedRule.evaluate(
      user({ inlinePolicies: [{ policyName: "Inline", document: ADMIN_DOCUMENT }] }),
    );
    assert.deepEqual(failTitles(verdicts, ""), [
      "IAM user has an inline policy with Action '*' on Resource '*'",
    ]);
  });

  test("does not look at group policies — that is a separate rule", () => {
    // Kept apart so the report can distinguish "this user is an admin" from
    // "this group makes everyone in it an admin", which have different fixes.
    assert.deepEqual(
      adminPolicyAttachedRule.evaluate(
        user({ groups: [groupWith("admins", ADMIN_DOCUMENT)] }),
      ),
      [{ status: "pass" }],
    );
  });

  test("reports an unreadable policy document as inconclusive", () => {
    // A document nobody could fetch is the one most likely to be interesting,
    // since GetPolicyVersion can be denied by the very boundary being audited.
    const verdicts = adminPolicyAttachedRule.evaluate(
      user({
        attachedPolicies: [
          {
            policyName: "Unknown",
            policyArn: "arn:aws:iam::000000000000:policy/Unknown",
            document: null,
          },
        ],
      }),
    );
    assert.equal(verdicts.length, 1);
    assert.equal(verdicts[0]?.status, "inconclusive");
  });

  test("is inconclusive when the policy lists could not be observed", () => {
    const verdicts = adminPolicyAttachedRule.evaluate(
      user({}, ["attachedPolicies"]),
    );
    assert.equal(verdicts.length, 1);
    assert.equal(verdicts[0]?.status, "inconclusive");
  });
});

// ---------------------------------------------------------------------------
// Administrative access inherited through a group
// ---------------------------------------------------------------------------

describe("iam-admin-policy-via-group", () => {
  test("finds an administrator whose user object looks completely harmless", () => {
    // This is the check the whole group-resolution machinery exists for. The
    // user below has no attached policies, no inline policies, no access keys,
    // and no console password — and is a full account administrator.
    const verdicts = adminViaGroupRule.evaluate(
      user({ groups: [groupWith("legacy-admins", ADMIN_DOCUMENT)] }),
    );
    assert.equal(verdicts.length, 1);
    assert.equal(verdicts[0]?.status, "fail");
    assert.equal(
      verdicts[0]?.status === "fail" && verdicts[0].title,
      undefined,
      "should use the rule's default title",
    );
  });

  test("finds it through an inline group policy too", () => {
    const verdicts = adminViaGroupRule.evaluate(
      user({ groups: [groupWith("legacy-admins", ADMIN_DOCUMENT, "inline")] }),
    );
    assert.equal(verdicts.length, 1);
    assert.equal(verdicts[0]?.status, "fail");
  });

  test("names the group so the reader knows who else is affected", () => {
    const verdicts = adminViaGroupRule.evaluate(
      user({ groups: [groupWith("legacy-admins", ADMIN_DOCUMENT)] }),
    );
    const verdict = verdicts[0]!;
    assert.equal(verdict.status, "fail");
    assert.match(verdict.detail, /legacy-admins/);
  });

  test("passes when the user's groups grant only scoped access", () => {
    assert.deepEqual(
      adminViaGroupRule.evaluate(
        user({ groups: [groupWith("readers", SCOPED_DOCUMENT)] }),
      ),
      [{ status: "pass" }],
    );
  });

  test("does not apply at all to a user in no groups", () => {
    // An empty array, not a pass: the pass count should mean "groups were
    // checked and found safe", not be padded with users who had no groups.
    assert.deepEqual(adminViaGroupRule.evaluate(user()), []);
  });

  test("is inconclusive when group membership could not be resolved", () => {
    // An unresolved group is precisely where an administrator hides, so this
    // must never round down to a pass.
    const verdicts = adminViaGroupRule.evaluate(user({}, ["groups"]));
    assert.equal(verdicts.length, 1);
    assert.equal(verdicts[0]?.status, "inconclusive");
  });
});

// ---------------------------------------------------------------------------
// Unrestricted iam:PassRole
// ---------------------------------------------------------------------------

describe("iam-unrestricted-passrole", () => {
  test("flags an inline policy passing any role", () => {
    const verdicts = unrestrictedPassRoleRule.evaluate(
      user({
        inlinePolicies: [
          {
            policyName: "PassRoleAnywhere",
            document: {
              Statement: [
                {
                  Sid: "PassAnyRole",
                  Effect: "Allow",
                  Action: ["iam:PassRole", "iam:AttachUserPolicy"],
                  Resource: "*",
                },
              ],
            },
          },
        ],
      }),
    );
    assert.deepEqual(failTitles(verdicts, ""), [
      "IAM user has an inline policy allowing unrestricted iam:PassRole",
    ]);
  });

  test("does not flag PassRole scoped to specific roles", () => {
    // Scoped PassRole is ordinary and necessary. Flagging it would bury the
    // unscoped case that actually escalates privilege.
    assert.deepEqual(
      unrestrictedPassRoleRule.evaluate(
        user({
          inlinePolicies: [
            {
              policyName: "PassAppRole",
              document: {
                Statement: [
                  {
                    Effect: "Allow",
                    Action: "iam:PassRole",
                    Resource: "arn:aws:iam::000000000000:role/app",
                  },
                ],
              },
            },
          ],
        }),
      ),
      [{ status: "pass" }],
    );
  });

  test("does not double-report a policy already flagged as full admin", () => {
    // Action "*" technically includes iam:PassRole, but it is already reported
    // under a headline describing the far larger problem. Counting it twice
    // would inflate the finding count without adding anything to fix.
    assert.deepEqual(
      unrestrictedPassRoleRule.evaluate(
        user({ inlinePolicies: [{ policyName: "Admin", document: ADMIN_DOCUMENT }] }),
      ),
      [{ status: "pass" }],
    );
  });

  test("still flags a service-scoped wildcard such as iam:*", () => {
    // "iam:*" is a genuine, targeted grant of PassRole rather than an incidental
    // consequence of account-wide admin, so it belongs to this rule.
    const verdicts = unrestrictedPassRoleRule.evaluate(
      user({
        inlinePolicies: [
          {
            policyName: "IamControl",
            document: {
              Statement: [
                { Effect: "Allow", Action: ["iam:*"], Resource: "*" },
              ],
            },
          },
        ],
      }),
    );
    assert.equal(verdicts.length, 1);
    assert.equal(verdicts[0]?.status, "fail");
  });

  test("flags a group-inherited grant under its own headline", () => {
    const verdicts = unrestrictedPassRoleRule.evaluate(
      user({
        groups: [
          groupWith("legacy-admins", {
            Statement: [
              { Effect: "Allow", Action: "iam:PassRole", Resource: "*" },
            ],
          }),
        ],
      }),
    );
    assert.deepEqual(failTitles(verdicts, ""), [
      "IAM user inherits an unrestricted iam:PassRole grant through group membership",
    ]);
  });

  test("does not flag a grant guarded by iam:PassedToService", () => {
    assert.deepEqual(
      unrestrictedPassRoleRule.evaluate(
        user({
          inlinePolicies: [
            {
              policyName: "PassToEc2",
              document: {
                Statement: [
                  {
                    Effect: "Allow",
                    Action: "iam:PassRole",
                    Resource: "*",
                    Condition: {
                      StringEquals: { "iam:PassedToService": "ec2.amazonaws.com" },
                    },
                  },
                ],
              },
            },
          ],
        }),
      ),
      [{ status: "pass" }],
    );
  });
});

// ---------------------------------------------------------------------------
// Console access without MFA
// ---------------------------------------------------------------------------

describe("iam-console-without-mfa", () => {
  test("flags a console user with no MFA device", () => {
    const verdicts = consoleWithoutMfaRule.evaluate(
      user({ hasConsoleAccess: true }),
    );
    assert.equal(verdicts.length, 1);
    assert.equal(verdicts[0]?.status, "fail");
  });

  test("passes a console user who has MFA", () => {
    assert.deepEqual(
      consoleWithoutMfaRule.evaluate(
        user({
          hasConsoleAccess: true,
          mfaDeviceIds: ["arn:aws:iam::000000000000:mfa/test-user"],
        }),
      ),
      [{ status: "pass" }],
    );
  });

  test("does not apply to a service account with no console password", () => {
    // There is no password to protect, so demanding MFA would be a false
    // positive — and the seeded read-only service account is exactly this case.
    assert.deepEqual(consoleWithoutMfaRule.evaluate(user()), []);
  });

  test("is inconclusive when console access or MFA could not be observed", () => {
    const verdicts = consoleWithoutMfaRule.evaluate(user({}, ["mfaDeviceIds"]));
    assert.equal(verdicts.length, 1);
    assert.equal(verdicts[0]?.status, "inconclusive");
  });
});

// ---------------------------------------------------------------------------
// Long-lived access keys
// ---------------------------------------------------------------------------

describe("iam-long-lived-access-key", () => {
  test("passes a user with no access keys", () => {
    assert.deepEqual(longLivedAccessKeyRule.evaluate(user()), [
      { status: "pass" },
    ]);
  });

  test("passes a recent key on a programmatic-only account", () => {
    // A young key on an account with no console password is the intended
    // configuration for a service identity.
    assert.deepEqual(
      longLivedAccessKeyRule.evaluate(user({ accessKeys: [accessKey()] })),
      [{ status: "pass" }],
    );
  });

  test("flags a key past the rotation window", () => {
    const verdicts = longLivedAccessKeyRule.evaluate(
      user({ accessKeys: [accessKey({ ageInDays: 200 })] }),
    );
    assert.equal(verdicts.length, 1);
    assert.equal(verdicts[0]?.status, "fail");
    const verdict = verdicts[0]!;
    assert.equal(verdict.status, "fail");
    assert.match(verdict.detail, /200 days old/);
  });

  test("flags even a brand-new key on a user who also has console access", () => {
    // CIS asks for this to be caught at account setup rather than 90 days
    // later, and it is the condition the seeded admin fixture triggers.
    const verdicts = longLivedAccessKeyRule.evaluate(
      user({ hasConsoleAccess: true, accessKeys: [accessKey({ ageInDays: 0 })] }),
    );
    assert.equal(verdicts.length, 1);
    const verdict = verdicts[0]!;
    assert.equal(verdict.status, "fail");
    assert.match(verdict.detail, /also has console access/);
  });

  test("ignores inactive keys", () => {
    // An inactive key cannot authenticate. Reporting it at the same level as a
    // live credential would misstate the risk.
    assert.deepEqual(
      longLivedAccessKeyRule.evaluate(
        user({
          hasConsoleAccess: true,
          accessKeys: [accessKey({ status: "Inactive", ageInDays: 900 })],
        }),
      ),
      [{ status: "pass" }],
    );
  });

  test("is inconclusive when a key's age is unknown", () => {
    // Unknown is not young.
    const verdicts = longLivedAccessKeyRule.evaluate(
      user({ accessKeys: [accessKey({ createdAt: null, ageInDays: null })] }),
    );
    assert.equal(verdicts.length, 1);
    assert.equal(verdicts[0]?.status, "inconclusive");
  });

  test("keys the finding by access key id so rotation resolves it", () => {
    const verdicts = longLivedAccessKeyRule.evaluate(
      user({ accessKeys: [accessKey({ ageInDays: 200 })] }),
    );
    assert.equal(
      verdicts[0]?.status === "fail" && verdicts[0].key,
      "AKIAIOSFODNN7EXAMPLE",
    );
  });

  test("is inconclusive when the key list could not be observed", () => {
    const verdicts = longLivedAccessKeyRule.evaluate(user({}, ["accessKeys"]));
    assert.equal(verdicts.length, 1);
    assert.equal(verdicts[0]?.status, "inconclusive");
  });
});
