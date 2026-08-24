/**
 * CloudSentinel — EC2 security group collector.
 *
 * Reads every security group in the target environment and converts it into the
 * normalized {@link SecurityGroupResource} shape from lib/types/resource.ts.
 *
 * Where it sits in the architecture: stage one of the pipeline, alongside the
 * S3 and IAM collectors.
 *
 *   LocalStack --> [ collectSecurityGroups ] --> SecurityGroupResource[] --> rules
 *
 * SECURITY: strictly read-only. Only `Describe*` commands appear in this file —
 * no `Authorize*`, `Revoke*`, `Create*`, or `Delete*`, and there must never be.
 * scripts/seed-localstack.ts is the only component allowed to change cloud
 * state.
 *
 * This is the simplest of the three collectors. Unlike S3, where every setting
 * needs its own API call, `DescribeSecurityGroups` returns each group complete
 * with its rules and tags in a single response. Almost all the work here is
 * reshaping AWS's `IpPermissions` structure into something a rule can read
 * without knowing SDK internals.
 *
 * The part that is easy to get dangerously wrong is how AWS encodes "open to
 * everything" — see {@link normalizeRules}. Two separate fields use absence and
 * a magic value to mean *maximum* exposure, so naive checks fail open: they
 * report a wide-open group as fine.
 */

import {
  DescribeSecurityGroupsCommand,
  type EC2Client,
  type IpPermission,
} from "@aws-sdk/client-ec2";

import { AWS_REGION, createEC2Client } from "../aws/localstack.ts";
import type {
  CollectionError,
  SecurityGroupResource,
  SecurityGroupRule,
} from "../types/resource.ts";

/**
 * What this collector returns: the groups it read, plus any non-fatal problems.
 * Same contract as the S3 collector — errors are returned, never thrown, so one
 * failure cannot abort an entire scan.
 */
export interface Ec2CollectionResult {
  resources: SecurityGroupResource[];
  errors: CollectionError[];
}

function awsErrorCode(error: unknown): string {
  if (typeof error !== "object" || error === null) return "";
  const candidate = error as { name?: string; Code?: string; code?: string };
  return candidate.name ?? candidate.Code ?? candidate.code ?? "";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

// ---------------------------------------------------------------------------
// Rule normalization
// ---------------------------------------------------------------------------

/**
 * Converts AWS `IpPermission` entries into {@link SecurityGroupRule}s.
 *
 * Two encodings in this data structure mean the opposite of what a careless
 * reader assumes, and both signal *more* exposure rather than less:
 *
 * 1. **`IpProtocol` of `"-1"` means every protocol**, not "no protocol" and not
 *    an error. A rule engine that only ever compares against `"tcp"` would walk
 *    straight past a group that is open on TCP, UDP, and ICMP at once. The
 *    value is preserved verbatim so the rule engine can test for it explicitly.
 *
 * 2. **Absent `FromPort`/`ToPort` means every port.** AWS omits the port fields
 *    entirely when the protocol is `-1`, and also for protocols like ICMP that
 *    have no ports. So `null` here must be read as "all ports", never as "no
 *    ports" — reading it the other way turns the single most severe possible
 *    rule into a silent pass. This is documented on the type as well, because
 *    it is the sort of thing that gets misread months later.
 *
 * One AWS permission entry is kept as one rule rather than being exploded into
 * one rule per CIDR. A group that allows tcp/22 from both `0.0.0.0/0` and
 * `::/0` is a single hole in the firewall, and reporting it as one finding that
 * names both ranges reads better than two near-identical findings.
 *
 * `UserIdGroupPairs` — references to other security groups — are collected
 * separately from CIDRs because they are generally the *desirable* pattern:
 * traffic scoped to peer instances rather than to an IP range. Rules should not
 * treat them the way they treat `0.0.0.0/0`.
 *
 * Exported for tests rather than as public API.
 */
export function normalizeRules(permissions: IpPermission[]): SecurityGroupRule[] {
  return permissions.map((permission) => {
    const descriptions: string[] = [];
    for (const range of permission.IpRanges ?? []) {
      if (range.Description) descriptions.push(range.Description);
    }
    for (const range of permission.Ipv6Ranges ?? []) {
      if (range.Description) descriptions.push(range.Description);
    }
    for (const pair of permission.UserIdGroupPairs ?? []) {
      if (pair.Description) descriptions.push(pair.Description);
    }

    return {
      // Defaulting to "-1" on an absent protocol is the fail-safe choice: if
      // AWS ever omitted the field, assuming "all protocols" over-reports
      // rather than under-reports, and a security tool should err loud.
      protocol: permission.IpProtocol ?? "-1",
      fromPort: permission.FromPort ?? null,
      toPort: permission.ToPort ?? null,
      ipv4Ranges: (permission.IpRanges ?? [])
        .map((range) => range.CidrIp)
        .filter((cidr): cidr is string => typeof cidr === "string"),
      ipv6Ranges: (permission.Ipv6Ranges ?? [])
        .map((range) => range.CidrIpv6)
        .filter((cidr): cidr is string => typeof cidr === "string"),
      sourceSecurityGroupIds: (permission.UserIdGroupPairs ?? [])
        .map((pair) => pair.GroupId)
        .filter((id): id is string => typeof id === "string"),
      descriptions,
    };
  });
}

/** Flattens AWS's `[{ Key, Value }]` tag array into a plain lookup object. */
function normalizeTags(
  tags: Array<{ Key?: string; Value?: string }>,
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const tag of tags) {
    if (tag.Key) result[tag.Key] = tag.Value ?? "";
  }
  return result;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Collects every security group visible to the configured credentials.
 *
 * Results are paginated: `DescribeSecurityGroups` caps a response at 1000
 * groups and hands back a `NextToken` when more remain. The loop below follows
 * that token to completion. Skipping pagination is a subtle and serious bug in
 * a security scanner — it produces a scan that looks successful while silently
 * ignoring every resource past the first page.
 *
 * @param collectedAt ISO-8601 timestamp stamped on every resource in this run.
 *                    Shared across all three collectors so a scan is one
 *                    coherent point-in-time snapshot.
 * @param client      Optional EC2 client, for tests. Defaults to the
 *                    LocalStack-pinned client, which refuses any non-loopback
 *                    endpoint.
 * @returns Groups collected and non-fatal errors. A failed API call leaves the
 *          resources gathered so far intact and records why; this function does
 *          not throw.
 */
export async function collectSecurityGroups(
  collectedAt: string = new Date().toISOString(),
  client: EC2Client = createEC2Client(),
): Promise<Ec2CollectionResult> {
  const errors: CollectionError[] = [];
  const resources: SecurityGroupResource[] = [];

  let nextToken: string | undefined;
  do {
    let page;
    try {
      page = await client.send(
        new DescribeSecurityGroupsCommand({ NextToken: nextToken }),
      );
    } catch (error) {
      // Recorded against the service rather than a named resource, because a
      // list failure means we learned nothing about any particular group.
      errors.push({
        resourceType: "security_group",
        resourceName: null,
        operation: "DescribeSecurityGroups",
        message: `${awsErrorCode(error) || "Error"}: ${errorMessage(error)}`,
      });
      break;
    }

    for (const group of page.SecurityGroups ?? []) {
      // A group without an id cannot be identified, referenced, or acted on, so
      // there is nothing useful to report about it.
      if (!group.GroupId) continue;

      const name = group.GroupName ?? group.GroupId;

      resources.push({
        // Security groups do have real ARNs, but they need the owning account
        // id, which only appears on the response as `OwnerId`. When it is
        // missing the raw `sg-...` id is used instead — still globally unique
        // within an account, which is all the `id` contract requires.
        id: group.OwnerId
          ? `arn:aws:ec2:${AWS_REGION}:${group.OwnerId}:security-group/${group.GroupId}`
          : group.GroupId,
        type: "security_group",
        name,
        region: AWS_REGION,
        tags: normalizeTags(group.Tags ?? []),
        collectedAt,
        // Always empty for security groups: DescribeSecurityGroups returns a
        // group complete in one response, so there is no per-setting call that
        // can fail on its own. Either the whole group was read or the group is
        // not in the inventory at all, and the list failure is recorded in
        // `errors` instead.
        unobserved: [],
        config: {
          groupId: group.GroupId,
          description: group.Description ?? "",
          vpcId: group.VpcId ?? null,
          ingressRules: normalizeRules(group.IpPermissions ?? []),
          egressRules: normalizeRules(group.IpPermissionsEgress ?? []),
        },
      });
    }

    nextToken = page.NextToken;
  } while (nextToken);

  // Stable ordering so two scans of an unchanged environment produce identical
  // output, which makes diffing scans meaningful.
  resources.sort((a, b) => a.name.localeCompare(b.name));

  return { resources, errors };
}
