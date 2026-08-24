/**
 * CloudSentinel — contract test for the captured inventory.
 *
 * Run with `npm test`. Reads the committed `fixtures/inventory.json` snapshot,
 * so it needs no Docker, no LocalStack, and no credentials.
 *
 * What this file is for: `scripts/seed-localstack.ts` promises thirteen
 * findings in its `EXPECTED_FINDINGS` list, and the rule engine will be written
 * against exactly those. This test asserts that the *data each finding depends
 * on* is actually present in the collector's output, and that the compliant
 * control resources really are clean.
 *
 * That makes it a contract between the two halves of the system. If a later
 * refactor drops a field, renames one, or quietly stops resolving group
 * policies, this fails immediately with a specific message — instead of the
 * rule engine silently producing zero findings and looking like good news.
 *
 * Regenerate the snapshot with:
 *
 *     npm run collect -- --out fixtures/inventory.json
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";

import type { Resource, ResourceInventory } from "../lib/types/resource.ts";

const inventory = JSON.parse(
  readFileSync(join(import.meta.dirname, "inventory.json"), "utf8"),
) as ResourceInventory;

/**
 * Finds one resource by type and name, failing the test with a useful message
 * if the fixture no longer contains it.
 *
 * The return type is `Extract<Resource, { type: T }>`, which is the
 * discriminated union paying off: `findResource(inv, "s3_bucket", ...)` returns
 * something whose `config` is known to be an `S3BucketConfig`, so the
 * assertions below get full type checking rather than `any`.
 */
function findResource<T extends Resource["type"]>(
  type: T,
  name: string,
): Extract<Resource, { type: T }> {
  const match = inventory.resources.find(
    (resource): resource is Extract<Resource, { type: T }> =>
      resource.type === type && resource.name === name,
  );
  assert.ok(match, `fixture is missing ${type} "${name}"`);
  return match;
}

describe("inventory snapshot", () => {
  test("was collected without errors or gaps", () => {
    // A snapshot taken from a partial scan would make every assertion below
    // untrustworthy, so this is checked before anything else.
    assert.deepEqual(inventory.errors, []);
    for (const resource of inventory.resources) {
      assert.deepEqual(
        resource.unobserved,
        [],
        `${resource.name} has unobserved fields`,
      );
    }
  });

  test("records the endpoint it came from", () => {
    // An inventory file outlives the shell that made it; without this it could
    // be mistaken for a snapshot of a different environment.
    assert.match(inventory.endpoint, /localhost|127\.0\.0\.1/);
  });
});

// ---------------------------------------------------------------------------
// The five S3 findings
// ---------------------------------------------------------------------------

describe("cloudsentinel-public-assets", () => {
  const bucket = () => findResource("s3_bucket", "cloudsentinel-public-assets");

  test("Block Public Access is fully disabled", () => {
    const pab = bucket().config.publicAccessBlock;
    assert.ok(pab, "expected a Block Public Access configuration");
    assert.equal(pab.blockPublicAcls, false);
    assert.equal(pab.ignorePublicAcls, false);
    assert.equal(pab.blockPublicPolicy, false);
    assert.equal(pab.restrictPublicBuckets, false);
  });

  test("the bucket policy grants s3:GetObject to Principal '*'", () => {
    const statements = bucket().config.policy?.Statement ?? [];
    const publicRead = statements.find(
      (statement) =>
        statement.Effect === "Allow" && statement.Principal === "*",
    );
    assert.ok(publicRead, "expected a statement with Principal '*'");
    assert.equal(publicRead.Action, "s3:GetObject");
  });

  test("the ACL grants READ to AllUsers", () => {
    const publicGrant = bucket().config.aclGrants.find((grant) =>
      grant.granteeId?.endsWith("/global/AllUsers"),
    );
    assert.ok(publicGrant, "expected an AllUsers grant");
    assert.equal(publicGrant.permission, "READ");
  });

  test("versioning is disabled", () => {
    assert.equal(bucket().config.versioning, "Disabled");
  });

  test("server access logging is off", () => {
    assert.equal(bucket().config.loggingEnabled, false);
  });
});

// ---------------------------------------------------------------------------
// The three security group findings
// ---------------------------------------------------------------------------

describe("cloudsentinel-open-mgmt", () => {
  const group = () => findResource("security_group", "cloudsentinel-open-mgmt");

  /** Finds an ingress rule covering `port`, whatever else it also covers. */
  function ruleForPort(port: number) {
    return group().config.ingressRules.find(
      (rule) =>
        rule.fromPort !== null &&
        rule.toPort !== null &&
        rule.fromPort <= port &&
        rule.toPort >= port,
    );
  }

  test("tcp/22 is open to 0.0.0.0/0", () => {
    const ssh = ruleForPort(22);
    assert.ok(ssh, "expected an ingress rule covering port 22");
    assert.equal(ssh.protocol, "tcp");
    assert.ok(ssh.ipv4Ranges.includes("0.0.0.0/0"));
  });

  test("tcp/22 is also open to ::/0", () => {
    // Collected separately because a group locked down on IPv4 and open on
    // IPv6 is still open, and IPv6 exposure is the half people forget.
    const ssh = ruleForPort(22);
    assert.ok(ssh?.ipv6Ranges.includes("::/0"));
  });

  test("tcp/3389 is open to 0.0.0.0/0", () => {
    const rdp = ruleForPort(3389);
    assert.ok(rdp, "expected an ingress rule covering port 3389");
    assert.ok(rdp.ipv4Ranges.includes("0.0.0.0/0"));
  });
});

// ---------------------------------------------------------------------------
// The four direct IAM findings
// ---------------------------------------------------------------------------

describe("cloudsentinel-admin-svc", () => {
  const user = () => findResource("iam_user", "cloudsentinel-admin-svc");

  test("has an attached policy allowing Action '*' on Resource '*'", () => {
    const wildcard = user().config.attachedPolicies.find((policy) =>
      policy.document?.Statement.some(
        (statement) =>
          statement.Effect === "Allow" &&
          statement.Action === "*" &&
          statement.Resource === "*",
      ),
    );
    assert.ok(wildcard, "expected an attached wildcard policy");
  });

  test("has an inline policy allowing unrestricted iam:PassRole", () => {
    const passRole = user().config.inlinePolicies.find((policy) =>
      policy.document?.Statement.some((statement) => {
        const actions = Array.isArray(statement.Action)
          ? statement.Action
          : [statement.Action];
        return actions.includes("iam:PassRole") && statement.Resource === "*";
      }),
    );
    assert.ok(passRole, "expected an inline iam:PassRole policy");
  });

  test("has console access but no MFA device", () => {
    // The conjunction is the finding. Either half alone is unremarkable.
    assert.equal(user().config.hasConsoleAccess, true);
    assert.deepEqual(user().config.mfaDeviceIds, []);
  });

  test("has a long-lived access key, with no secret recorded", () => {
    const keys = user().config.accessKeys;
    assert.equal(keys.length, 1);
    assert.equal(keys[0]?.status, "Active");
    assert.ok(typeof keys[0]?.ageInDays === "number");

    // The collector must never capture key secrets, even throwaway ones.
    assert.ok(!JSON.stringify(keys).toLowerCase().includes("secret"));
  });
});

// ---------------------------------------------------------------------------
// The group-inheritance finding
// ---------------------------------------------------------------------------

describe("cloudsentinel-group-member", () => {
  const user = () => findResource("iam_user", "cloudsentinel-group-member");

  test("looks harmless at the user level", () => {
    // This is the premise of the finding: everything a user-level check can
    // see about this account is empty.
    assert.deepEqual(user().config.attachedPolicies, []);
    assert.deepEqual(user().config.inlinePolicies, []);
    assert.deepEqual(user().config.accessKeys, []);
    assert.equal(user().config.hasConsoleAccess, false);
  });

  test("inherits Action '*' on Resource '*' through a group", () => {
    const admin = user().config.groups.flatMap((group) =>
      group.attachedPolicies.filter((policy) =>
        policy.document?.Statement.some(
          (statement) =>
            statement.Effect === "Allow" &&
            statement.Action === "*" &&
            statement.Resource === "*",
        ),
      ),
    );
    assert.equal(admin.length, 1, "expected one inherited wildcard policy");
  });

  test("group inline policies are resolved too, not just managed ones", () => {
    // Both resolution paths matter: managed policies need GetPolicyVersion,
    // inline ones need GetGroupPolicy. Only testing one would let the other
    // silently break.
    const inline = user().config.groups.flatMap((group) => group.inlinePolicies);
    assert.equal(inline.length, 1);
    assert.ok(inline[0]?.document, "group inline policy document was not resolved");
  });
});

// ---------------------------------------------------------------------------
// The compliant control group
// ---------------------------------------------------------------------------

describe("compliant controls", () => {
  test("the private bucket blocks public access and has versioning on", () => {
    const bucket = findResource("s3_bucket", "cloudsentinel-private-logs");
    const pab = bucket.config.publicAccessBlock;

    assert.ok(pab);
    assert.equal(pab.blockPublicAcls, true);
    assert.equal(pab.ignorePublicAcls, true);
    assert.equal(pab.blockPublicPolicy, true);
    assert.equal(pab.restrictPublicBuckets, true);
    assert.equal(bucket.config.versioning, "Enabled");
    assert.equal(bucket.config.policy, null);

    // Logging is on and points at itself. The control group is only a useful
    // baseline if it is clean under every rule, including the access-logging
    // check — otherwise "the controls produce no findings" comes with an
    // asterisk.
    assert.equal(bucket.config.loggingEnabled, true);
    assert.equal(bucket.config.loggingTargetBucket, "cloudsentinel-private-logs");

    // Not "no grants at all": every bucket ACL carries a FULL_CONTROL grant to
    // the bucket owner, which is ordinary and not a finding. What must be
    // absent is a grant to one of the two public groups.
    const publicGrants = bucket.config.aclGrants.filter((grant) =>
      grant.granteeId?.includes("/global/"),
    );
    assert.deepEqual(publicGrants, []);
  });

  test("the restricted security group exposes nothing to the internet", () => {
    const group = findResource("security_group", "cloudsentinel-restricted-app");

    for (const rule of group.config.ingressRules) {
      assert.ok(!rule.ipv4Ranges.includes("0.0.0.0/0"));
      assert.ok(!rule.ipv6Ranges.includes("::/0"));
    }
  });

  test("the read-only user has no console access, keys, or wildcard grants", () => {
    const user = findResource("iam_user", "cloudsentinel-readonly-svc");

    assert.equal(user.config.hasConsoleAccess, false);
    assert.deepEqual(user.config.accessKeys, []);
    assert.deepEqual(user.config.groups, []);

    const statements = user.config.inlinePolicies.flatMap(
      (policy) => policy.document?.Statement ?? [],
    );
    assert.ok(statements.length > 0, "expected a scoped inline policy");
    for (const statement of statements) {
      assert.notEqual(statement.Action, "*");
      assert.notEqual(statement.Resource, "*");
    }
  });
});
