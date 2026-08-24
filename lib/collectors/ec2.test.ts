/**
 * CloudSentinel — tests for the EC2 security group collector.
 *
 * Run with `npm test`. No network, no LocalStack: these exercise the pure
 * reshaping of AWS's `IpPermission` structure.
 *
 * The cases below are chosen around the two encodings that mean *maximum*
 * exposure while looking like absence — protocol `"-1"` and missing port
 * fields. Both are easy to misread as "nothing here", and misreading them
 * turns the most severe possible firewall rule into a silent pass. Tests are
 * the cheapest way to keep that from being reintroduced.
 */

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { normalizeRules } from "./ec2.ts";

describe("normalizeRules", () => {
  test("keeps IPv4 and IPv6 ranges from one permission on one rule", () => {
    // A group open on tcp/22 to both address families is a single hole in the
    // firewall. Splitting it into two rules would produce two near-identical
    // findings for what a reader thinks of as one problem.
    const rules = normalizeRules([
      {
        IpProtocol: "tcp",
        FromPort: 22,
        ToPort: 22,
        IpRanges: [{ CidrIp: "0.0.0.0/0", Description: "SSH from anywhere" }],
        Ipv6Ranges: [{ CidrIpv6: "::/0" }],
      },
    ]);

    assert.equal(rules.length, 1);
    assert.deepEqual(rules[0]?.ipv4Ranges, ["0.0.0.0/0"]);
    assert.deepEqual(rules[0]?.ipv6Ranges, ["::/0"]);
    assert.deepEqual(rules[0]?.descriptions, ["SSH from anywhere"]);
  });

  test("protocol -1 with absent ports is preserved, not defaulted away", () => {
    // "-1" means every protocol and the absent ports mean every port. Null
    // here must read as "all ports", never as "no ports".
    const rules = normalizeRules([
      { IpProtocol: "-1", IpRanges: [{ CidrIp: "0.0.0.0/0" }] },
    ]);

    assert.equal(rules[0]?.protocol, "-1");
    assert.equal(rules[0]?.fromPort, null);
    assert.equal(rules[0]?.toPort, null);
    assert.deepEqual(rules[0]?.ipv4Ranges, ["0.0.0.0/0"]);
  });

  test("a missing protocol falls back to -1 rather than to a specific one", () => {
    // Fail loud: assuming "all protocols" over-reports, assuming "tcp" would
    // hide exposure on every other protocol.
    const rules = normalizeRules([{ IpRanges: [{ CidrIp: "10.0.0.0/8" }] }]);

    assert.equal(rules[0]?.protocol, "-1");
  });

  test("separates peer security group references from CIDR ranges", () => {
    // Group-to-group references are the desirable pattern — traffic scoped to
    // peer instances — so a rule must be able to tell them apart from an open
    // IP range instead of flagging both.
    const rules = normalizeRules([
      {
        IpProtocol: "tcp",
        FromPort: 5432,
        ToPort: 5432,
        UserIdGroupPairs: [
          { GroupId: "sg-abc123", Description: "app tier" },
          { GroupId: "sg-def456" },
        ],
      },
    ]);

    assert.deepEqual(rules[0]?.sourceSecurityGroupIds, ["sg-abc123", "sg-def456"]);
    assert.deepEqual(rules[0]?.ipv4Ranges, []);
    assert.deepEqual(rules[0]?.ipv6Ranges, []);
  });

  test("returns an empty list for a group with no rules", () => {
    assert.deepEqual(normalizeRules([]), []);
  });
});
