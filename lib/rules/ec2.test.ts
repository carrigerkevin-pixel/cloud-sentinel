/**
 * CloudSentinel — tests for the security group compliance rules.
 *
 * Run with `npm test`. Uses Node's built-in test runner, so no test framework
 * dependency and no Docker, LocalStack, or credentials are needed.
 *
 * The cases below concentrate on the four ways this rule could be wrong in a
 * way nobody would notice:
 *
 *   1. Missing the IPv6 half of an exposure. A group tightened on IPv4 and left
 *      open on `::/0` is still wide open, and the AWS console makes it easy to
 *      fix one and forget the other.
 *   2. Misreading AWS's encodings for "every port" — protocol `-1`, and null
 *      port fields. Reading null as "no ports" instead of "all ports" would
 *      make the rule silently ignore the most exposed groups there are.
 *   3. Flagging traffic scoped to a peer security group, which is the correct
 *      pattern and must not be penalised.
 *   4. Flagging ordinary public web ports, which would bury the real findings
 *      in noise.
 */

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import type {
  SecurityGroupConfig,
  SecurityGroupResource,
  SecurityGroupRule,
} from "../types/resource.ts";
import { unrestrictedIngressRule } from "./ec2.ts";
import type { RuleVerdict } from "./types.ts";

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

/** Builds one normalized ingress rule, defaulting to a closed one. */
function ingress(overrides: Partial<SecurityGroupRule> = {}): SecurityGroupRule {
  return {
    protocol: "tcp",
    fromPort: 443,
    toPort: 443,
    ipv4Ranges: [],
    ipv6Ranges: [],
    sourceSecurityGroupIds: [],
    descriptions: [],
    ...overrides,
  };
}

/** Builds a security group resource carrying the given ingress rules. */
function group(
  ingressRules: SecurityGroupRule[],
  unobserved: string[] = [],
): SecurityGroupResource {
  const config: SecurityGroupConfig = {
    groupId: "sg-0123456789abcdef0",
    description: "test group",
    vpcId: "vpc-0123456789abcdef0",
    ingressRules,
    // Every fixture group has open egress; it is deliberately not a rule yet,
    // for the reason set out in the header of lib/rules/ec2.ts.
    egressRules: [
      ingress({ protocol: "-1", fromPort: null, toPort: null, ipv4Ranges: ["0.0.0.0/0"] }),
    ],
  };

  return {
    id: "arn:aws:ec2:us-east-1:000000000000:security-group/sg-0123456789abcdef0",
    type: "security_group",
    name: "test-group",
    region: "us-east-1",
    tags: {},
    collectedAt: "2026-08-25T00:00:00.000Z",
    unobserved,
    config,
  };
}

/** Titles of the failing verdicts, in order — the most useful thing to assert. */
function failTitles(verdicts: RuleVerdict[]): string[] {
  return verdicts
    .filter((verdict) => verdict.status === "fail")
    .map((verdict) => (verdict.status === "fail" ? (verdict.title ?? "") : ""));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ec2-unrestricted-ingress", () => {
  test("passes on a group with no rules open to the world", () => {
    assert.deepEqual(
      unrestrictedIngressRule.evaluate(
        group([ingress({ ipv4Ranges: ["10.0.0.0/16"] })]),
      ),
      [{ status: "pass" }],
    );
  });

  test("passes on a group with no ingress at all", () => {
    // The untouched default VPC security group has this shape, and it must not
    // produce noise.
    assert.deepEqual(unrestrictedIngressRule.evaluate(group([])), [
      { status: "pass" },
    ]);
  });

  test("flags SSH open to the world on IPv4", () => {
    const verdicts = unrestrictedIngressRule.evaluate(
      group([
        ingress({ fromPort: 22, toPort: 22, ipv4Ranges: ["0.0.0.0/0"] }),
      ]),
    );
    assert.deepEqual(failTitles(verdicts), [
      "Security group allows 0.0.0.0/0 on tcp/22 (SSH)",
    ]);
  });

  test("flags IPv4 and IPv6 exposure of the same port separately", () => {
    // One rule entry can carry both families at once, which is exactly how the
    // seeded fixture is shaped. Each has to be closed on its own, so each gets
    // its own finding rather than being merged into one.
    const verdicts = unrestrictedIngressRule.evaluate(
      group([
        ingress({
          fromPort: 22,
          toPort: 22,
          ipv4Ranges: ["0.0.0.0/0"],
          ipv6Ranges: ["::/0"],
        }),
      ]),
    );
    assert.deepEqual(failTitles(verdicts), [
      "Security group allows 0.0.0.0/0 on tcp/22 (SSH)",
      "Security group allows ::/0 on tcp/22 (SSH over IPv6)",
    ]);
  });

  test("flags an IPv6-only exposure that IPv4 checks would miss", () => {
    const verdicts = unrestrictedIngressRule.evaluate(
      group([
        ingress({ fromPort: 3389, toPort: 3389, ipv6Ranges: ["::/0"] }),
      ]),
    );
    assert.deepEqual(failTitles(verdicts), [
      "Security group allows ::/0 on tcp/3389 (RDP over IPv6)",
    ]);
  });

  test("catches a sensitive port inside a wide range", () => {
    // A rule opening 20-30 is not obviously an SSH rule, but it is one.
    const verdicts = unrestrictedIngressRule.evaluate(
      group([ingress({ fromPort: 20, toPort: 30, ipv4Ranges: ["0.0.0.0/0"] })]),
    );
    assert.deepEqual(failTitles(verdicts), [
      "Security group allows 0.0.0.0/0 on tcp/22 (SSH)",
      "Security group allows 0.0.0.0/0 on tcp/23 (Telnet)",
    ]);
  });

  test("reports an all-protocols rule as one finding, not one per port", () => {
    // Protocol -1 with null ports means everything. Fourteen findings here
    // would bury the headline, which is that the whole group is open.
    const verdicts = unrestrictedIngressRule.evaluate(
      group([
        ingress({
          protocol: "-1",
          fromPort: null,
          toPort: null,
          ipv4Ranges: ["0.0.0.0/0"],
        }),
      ]),
    );
    assert.deepEqual(failTitles(verdicts), [
      "Security group allows 0.0.0.0/0 on all ports",
    ]);
  });

  test("treats an explicit 0-65535 range as all ports", () => {
    const verdicts = unrestrictedIngressRule.evaluate(
      group([
        ingress({ fromPort: 0, toPort: 65535, ipv4Ranges: ["0.0.0.0/0"] }),
      ]),
    );
    assert.deepEqual(failTitles(verdicts), [
      "Security group allows 0.0.0.0/0 on all ports",
    ]);
  });

  test("does not flag ordinary public web ports", () => {
    // Serving HTTPS to the internet is the intended configuration for most
    // fleets. Reporting it would train the reader to skim past everything.
    assert.deepEqual(
      unrestrictedIngressRule.evaluate(
        group([
          ingress({ fromPort: 80, toPort: 80, ipv4Ranges: ["0.0.0.0/0"] }),
          ingress({ fromPort: 443, toPort: 443, ipv4Ranges: ["0.0.0.0/0"] }),
        ]),
      ),
      [{ status: "pass" }],
    );
  });

  test("does not flag SSH scoped to a peer security group", () => {
    // Group-to-group references are the right answer, and flagging them would
    // penalise the fix this rule's remediation actually recommends.
    assert.deepEqual(
      unrestrictedIngressRule.evaluate(
        group([
          ingress({
            fromPort: 22,
            toPort: 22,
            sourceSecurityGroupIds: ["sg-bastion"],
          }),
        ]),
      ),
      [{ status: "pass" }],
    );
  });

  test("does not flag SSH from a narrow CIDR", () => {
    assert.deepEqual(
      unrestrictedIngressRule.evaluate(
        group([
          ingress({ fromPort: 22, toPort: 22, ipv4Ranges: ["203.0.113.0/24"] }),
        ]),
      ),
      [{ status: "pass" }],
    );
  });

  test("rates database ports high rather than critical", () => {
    // An exposed database usually means data loss; an exposed admin port
    // usually means a shell. Ranking them identically would flatten the
    // report's ordering into uselessness.
    const verdicts = unrestrictedIngressRule.evaluate(
      group([ingress({ fromPort: 5432, toPort: 5432, ipv4Ranges: ["0.0.0.0/0"] })]),
    );
    assert.equal(verdicts.length, 1);
    assert.equal(verdicts[0]?.status === "fail" && verdicts[0].severity, "high");
  });

  test("produces stable keys derived from the configuration", () => {
    // Finding ids are built from these, so they must not depend on array
    // position — reordering a group's rules must not renumber every finding.
    const verdicts = unrestrictedIngressRule.evaluate(
      group([
        ingress({
          fromPort: 22,
          toPort: 22,
          ipv4Ranges: ["0.0.0.0/0"],
          ipv6Ranges: ["::/0"],
        }),
      ]),
    );
    assert.deepEqual(
      verdicts.map((verdict) => (verdict.status === "fail" ? verdict.key : null)),
      ["ipv4:tcp/22", "ipv6:tcp/22"],
    );
  });

  test("includes the rule description as context when AWS supplies one", () => {
    const verdicts = unrestrictedIngressRule.evaluate(
      group([
        ingress({
          fromPort: 22,
          toPort: 22,
          ipv4Ranges: ["0.0.0.0/0"],
          descriptions: ["SSH from anywhere"],
        }),
      ]),
    );
    const verdict = verdicts[0]!;
    assert.equal(verdict.status, "fail");
    assert.match(verdict.detail, /SSH from anywhere/);
  });

  test("is inconclusive, not passing, when ingress could not be observed", () => {
    const verdicts = unrestrictedIngressRule.evaluate(group([], ["ingressRules"]));
    assert.equal(verdicts.length, 1);
    assert.equal(verdicts[0]?.status, "inconclusive");
  });
});
