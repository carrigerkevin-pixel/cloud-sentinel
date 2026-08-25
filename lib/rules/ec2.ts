/**
 * CloudSentinel — EC2 security group compliance rules.
 *
 * Checks over the {@link SecurityGroupResource} shape produced by
 * lib/collectors/ec2.ts. Exported as {@link EC2_RULES} and registered in
 * lib/rules/engine.ts.
 *
 * Where it sits in the architecture: stage two of the pipeline, alongside
 * lib/rules/s3.ts and lib/rules/iam.ts. Pure functions over already-collected
 * data — no AWS SDK, no network, no credentials.
 *
 *   SecurityGroupResource --> [ these rules ] --> RuleVerdict[] --> Finding[]
 *
 * What this file is really looking for: a security group is the instance-level
 * firewall, and the single most common way an EC2 fleet gets compromised is an
 * administration port left open to the whole internet. Exposed SSH and RDP are
 * scanned continuously by automated botnets — a fresh instance with tcp/22 open
 * to 0.0.0.0/0 typically starts receiving credential-stuffing attempts within
 * minutes, long before anyone has hardened it.
 *
 * Two deliberate scoping decisions, both about false positives:
 *
 *   - Ordinary web ports (80, 443) open to the world are NOT flagged. That is
 *     the intended configuration for the majority of internet-facing fleets,
 *     and a scanner that reports it as a problem teaches its users to skim past
 *     everything it says. Only remote-administration and data-store ports —
 *     the ones with no legitimate reason to face the internet — are reported.
 *   - Rules whose source is another security group are never flagged. Group-to-
 *     group references are the *correct* pattern: they scope traffic to peer
 *     instances rather than to an IP range, and flagging them would penalise
 *     the right answer.
 *
 * Deliberately not implemented yet, and noted here so it is not rediscovered as
 * an oversight: unrestricted *egress* (CIS 5.4-adjacent) and the CIS check that
 * the default VPC security group restrict all traffic. Both would fire on every
 * security group in the current fixtures, including the compliant control and
 * the untouched default group, which would make the Phase 3 contract test
 * meaningless. They belong with a suppression/exception mechanism, which
 * CloudSentinel does not have yet.
 */

import type {
  SecurityGroupResource,
  SecurityGroupRule,
} from "../types/resource.ts";
import { unobservedVerdict } from "./types.ts";
import type { Rule, RuleVerdict, Severity } from "./types.ts";

// ---------------------------------------------------------------------------
// Port classification
// ---------------------------------------------------------------------------

/** One port worth reporting on when it is reachable from the internet. */
interface SensitivePort {
  port: number;
  /** Short name used in the finding headline, e.g. `"SSH"`. */
  label: string;
  /**
   * `admin` ports are remote-administration ports — the ones CIS singles out.
   * Reaching one is a direct path to a shell, so they are `critical`.
   * `datastore` ports front a database or cache. Exposure usually means data
   * loss rather than immediate code execution, so they are `high`.
   */
  kind: "admin" | "datastore";
}

/**
 * Ports CloudSentinel reports on when they are open to the entire internet.
 *
 * The `admin` entries are exactly the remote server administration ports named
 * by CIS AWS Foundations 5.2/5.3. The `datastore` entries come from the AWS
 * Foundational Security Best Practices high-risk port list; they are included
 * because an internet-facing database is one of the most reliable ways to lose
 * an entire dataset at once, and unlike SSH it often has no second factor at
 * all.
 *
 * Kept as an explicit list rather than "anything that is not 80 or 443" so that
 * every finding this rule produces can name the service involved — "tcp/5432
 * (PostgreSQL)" is actionable in a way that "tcp/5432" is not.
 */
const SENSITIVE_PORTS: readonly SensitivePort[] = [
  { port: 22, label: "SSH", kind: "admin" },
  { port: 3389, label: "RDP", kind: "admin" },
  { port: 23, label: "Telnet", kind: "admin" },
  { port: 5985, label: "WinRM", kind: "admin" },
  { port: 5986, label: "WinRM over HTTPS", kind: "admin" },
  { port: 445, label: "SMB", kind: "admin" },
  { port: 1433, label: "MSSQL", kind: "datastore" },
  { port: 1521, label: "Oracle", kind: "datastore" },
  { port: 3306, label: "MySQL", kind: "datastore" },
  { port: 5432, label: "PostgreSQL", kind: "datastore" },
  { port: 6379, label: "Redis", kind: "datastore" },
  { port: 9200, label: "Elasticsearch", kind: "datastore" },
  { port: 11211, label: "Memcached", kind: "datastore" },
  { port: 27017, label: "MongoDB", kind: "datastore" },
];

/**
 * The CIDR blocks that mean "the entire internet", one per IP family.
 *
 * Matched as exact strings. A near-miss such as `0.0.0.0/1` is technically half
 * the internet and would not be caught here — an acknowledged limitation,
 * recorded rather than papered over, because implementing real CIDR arithmetic
 * to catch a spelling nobody actually uses would add a class of subtle bugs for
 * no practical gain. The two canonical forms below are what appears in real
 * configurations and in the AWS console's "Anywhere" option.
 */
const WORLD_CIDRS = {
  ipv4: "0.0.0.0/0",
  ipv6: "::/0",
} as const;

/**
 * Whether an ingress rule covers a given TCP/UDP port.
 *
 * Two AWS encodings both mean "every port" and must not be missed:
 * protocol `-1` (all protocols, where AWS omits the port fields entirely), and
 * an explicit `fromPort`/`toPort` of `null` on a protocol that does have ports.
 * Reading `null` as "no ports" instead of "all ports" is the exact inversion
 * that would make this rule silently ignore the widest-open groups there are.
 */
function coversPort(rule: SecurityGroupRule, port: number): boolean {
  if (rule.protocol === "-1") return true;
  if (rule.fromPort === null || rule.toPort === null) return true;
  return port >= rule.fromPort && port <= rule.toPort;
}

/**
 * Whether an ingress rule opens the full port range rather than a specific
 * service.
 *
 * Worth detecting separately: a group open on every port is not "fourteen
 * findings, one per sensitive port" — it is one much larger problem, and
 * reporting it as a list of individual ports would bury the headline.
 */
function coversAllPorts(rule: SecurityGroupRule): boolean {
  if (rule.protocol === "-1") return true;
  if (rule.fromPort === null || rule.toPort === null) return true;
  return rule.fromPort === 0 && rule.toPort === 65535;
}

/** Human-readable protocol for a finding headline. */
function protocolLabel(rule: SecurityGroupRule): string {
  return rule.protocol === "-1" ? "all protocols" : rule.protocol;
}

// ---------------------------------------------------------------------------
// Rule: unrestricted ingress to sensitive ports
// ---------------------------------------------------------------------------

/**
 * Flags security groups that allow inbound traffic from the entire internet to
 * a remote-administration or data-store port.
 *
 * Both IP families are checked independently, because they are independently
 * exploitable and independently forgotten. A group locked down on IPv4 but left
 * open on `::/0` is wide open — and this is a genuinely common mistake, since
 * the AWS console adds the IPv6 entry as a separate row that is easy to leave
 * behind when tightening the IPv4 one. The seeded fixture reproduces exactly
 * that shape: tcp/22 open on both `0.0.0.0/0` and `::/0`.
 *
 * One verdict is emitted per (port, IP family) pair, so closing SSH on IPv4
 * resolves precisely that finding and leaves the IPv6 one standing until it is
 * closed too.
 */
export const unrestrictedIngressRule: Rule<"security_group"> = {
  id: "ec2-unrestricted-ingress",
  title: "Security group allows unrestricted inbound access to a sensitive port",
  description:
    "Remote administration and database ports reachable from 0.0.0.0/0 or " +
    "::/0 are scanned and brute-forced continuously by automated attackers. " +
    "Access should be restricted to a bastion host, a VPN range, or a peer " +
    "security group.",
  severity: "critical",
  benchmark: "CIS AWS Foundations v3.0.0 5.2 / 5.3",
  remediation:
    "Revoke the open rule and re-add it scoped to a specific source, e.g. " +
    "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp " +
    "--port 22 --cidr 0.0.0.0/0, then allow the bastion's security group " +
    "with --source-group instead. Prefer AWS Systems Manager Session Manager " +
    "over opening an administration port at all.",
  appliesTo: "security_group",

  evaluate(group: SecurityGroupResource): RuleVerdict[] {
    if (group.unobserved.includes("ingressRules")) {
      return [
        unobservedVerdict(
          "ingressRules",
          "it cannot tell which sources are permitted inbound",
        ),
      ];
    }

    const verdicts: RuleVerdict[] = [];

    for (const rule of group.config.ingressRules) {
      // Each family is evaluated on its own so that the finding names the
      // exact CIDR the reader has to go and remove.
      const families: Array<{ family: "ipv4" | "ipv6"; cidr: string }> = [];
      if (rule.ipv4Ranges.includes(WORLD_CIDRS.ipv4)) {
        families.push({ family: "ipv4", cidr: WORLD_CIDRS.ipv4 });
      }
      if (rule.ipv6Ranges.includes(WORLD_CIDRS.ipv6)) {
        families.push({ family: "ipv6", cidr: WORLD_CIDRS.ipv6 });
      }
      if (families.length === 0) continue;

      const context = rule.descriptions.length
        ? ` Rule description: ${rule.descriptions.join("; ")}.`
        : "";

      for (const { family, cidr } of families) {
        const ipv6Suffix = family === "ipv6" ? " over IPv6" : "";

        if (coversAllPorts(rule)) {
          // Reported as a single finding rather than one per sensitive port:
          // the problem is the group, not any individual service behind it.
          verdicts.push({
            status: "fail",
            key: `${family}:all-ports`,
            title: `Security group allows ${cidr} on all ports${ipv6Suffix}`,
            detail:
              `Ingress rule permits ${protocolLabel(rule)} on every port from ` +
              `${cidr}. Every service on an attached instance is reachable ` +
              `from the internet.${context}`,
          });
          continue;
        }

        for (const sensitive of SENSITIVE_PORTS) {
          if (!coversPort(rule, sensitive.port)) continue;

          // Administration ports are a direct route to a shell; data-store
          // ports are usually a route to the data instead. Both are serious,
          // but ranking them differently keeps the report's ordering honest.
          const severity: Severity =
            sensitive.kind === "admin" ? "critical" : "high";
          const portSpec = `${rule.protocol}/${sensitive.port}`;

          verdicts.push({
            status: "fail",
            key: `${family}:${portSpec}`,
            severity,
            title: `Security group allows ${cidr} on ${portSpec} (${sensitive.label}${ipv6Suffix})`,
            detail:
              `Ingress rule permits ${portSpec} (${sensitive.label}) from ` +
              `${cidr}, covering port range ${rule.fromPort ?? "any"}-` +
              `${rule.toPort ?? "any"}.${context}`,
          });
        }
      }
    }

    return verdicts.length > 0 ? verdicts : [{ status: "pass" }];
  },
};

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/** Every security group rule, in evaluation and display order. */
export const EC2_RULES: readonly Rule<"security_group">[] = [
  unrestrictedIngressRule,
];
