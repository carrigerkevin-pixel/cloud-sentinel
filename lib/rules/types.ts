/**
 * CloudSentinel — rule engine types.
 *
 * This file defines the vocabulary the rule engine speaks: what a *rule* is,
 * what a rule is allowed to say about a resource, and what a *finding* looks
 * like once the engine has recorded it. Like lib/types/resource.ts it contains
 * types and small constants only — the rules themselves live in
 * lib/rules/{s3,ec2,iam}.ts and the runner lives in lib/rules/engine.ts.
 *
 * Where it sits in the architecture:
 *
 *   collectors --> ResourceInventory --> [ rule engine ] --> Finding[] --> dashboard
 *                                              ^                             |
 *                                              |                             +--> Postgres
 *                                        this file's types
 *
 * Three design decisions are worth understanding before reading the rules.
 *
 * 1. A rule verdict has *three* states, not two.
 *
 *    The collectors record an `unobserved` list naming settings they could not
 *    read (see lib/types/resource.ts). A rule that ignores that list and reads
 *    a `null` config field as "the setting is off" will confidently report a
 *    clean result about a resource it never actually inspected. So a rule may
 *    answer `pass`, `fail`, or `inconclusive`, and `inconclusive` is a
 *    first-class outcome that shows up in the report — never silently dropped
 *    and never rounded down to `pass`. A security scanner's worst failure mode
 *    is a false negative, because nothing about the output invites a second
 *    look.
 *
 * 2. A rule may emit more than one verdict for a single resource.
 *
 *    One security group can be open on tcp/22 over IPv4 *and* tcp/3389 over
 *    IPv4 *and* tcp/22 over IPv6. Those are three separate things to fix, so
 *    they are three separate findings, distinguished by the verdict's `key`.
 *    Collapsing them into one finding would mean closing SSH marks the whole
 *    finding resolved while RDP is still open to the internet.
 *
 * 3. Metadata lives on the rule, evidence lives on the verdict.
 *
 *    Severity, remediation text, and benchmark reference are fixed properties
 *    of the rule and are written once in its definition. The verdict carries
 *    only what varies per resource: the specific evidence. This keeps the rule
 *    bodies short enough to read as security logic rather than as string
 *    assembly, and it guarantees every finding from a given rule gives the same
 *    remediation advice.
 *
 * On the benchmark references: control identifiers follow the CIS AWS
 * Foundations Benchmark v3.0.0 and the AWS Foundational Security Best Practices
 * (FSBP) standard where a matching control exists. They are recorded for
 * orientation — so a reader can look the check up — and should be re-verified
 * against the current benchmark revision before this tool is pointed at a real
 * account, since CIS renumbers controls between major versions.
 */

import type { Resource, ResourceType } from "../types/resource.ts";

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/**
 * How much a finding matters.
 *
 * Deliberately a four-level scale rather than a numeric score. A number invites
 * false precision ("is this a 7 or an 8?") that nobody can defend in a review,
 * whereas four named buckets force a decision that can be argued about
 * concretely. The numeric risk score the dashboard shows is derived from these
 * by {@link SEVERITY_WEIGHT}, so the weighting is defined in exactly one place.
 *
 * The rough rubric used when assigning severities in this project:
 *
 *   - `critical` — reachable by an anonymous attacker from the internet, or
 *     grants unrestricted control of the account. Public S3 data, management
 *     ports open to 0.0.0.0/0, Action "*" on Resource "*".
 *   - `high`     — a strong privilege-escalation path or a missing
 *     authentication control that an attacker needs one other foothold to use.
 *   - `medium`   — weakens recovery or investigation after an incident rather
 *     than enabling one: no versioning, no access logging.
 *   - `low`      — hygiene worth fixing but not exploitable on its own.
 */
export type Severity = "critical" | "high" | "medium" | "low";

/**
 * Relative weight of each severity, used to compute the aggregate risk score.
 *
 * The gaps are wide on purpose: one critical finding should dominate a pile of
 * low ones, because ten missing tags are not equivalent to one world-readable
 * bucket. A linear 4/3/2/1 scale would let noise drown out the thing that
 * actually gets an account breached.
 */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 8,
  low: 2,
};

/**
 * Severities ordered most to least serious.
 *
 * Used for sorting findings and for `--fail-on` threshold comparisons, so that
 * "at least high" means critical *and* high without anyone writing that
 * ordering out a second time somewhere else.
 */
export const SEVERITY_ORDER: readonly Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
];

// ---------------------------------------------------------------------------
// What a rule returns
// ---------------------------------------------------------------------------

/**
 * A rule's answer about one resource.
 *
 * `pass` carries no evidence because there is nothing to show — the engine only
 * counts it. `fail` and `inconclusive` both carry a `detail` string, which must
 * quote the *actual observed values* rather than restating the rule. "Block
 * Public Access is absent; ACL grants READ to AllUsers" is useful; "bucket is
 * public" is not, because the reader still has to go and look up why.
 */
export type RuleVerdict =
  | { status: "pass" }
  | {
      /** The rule's condition was met: this resource has the problem. */
      status: "fail";
      /** Observed evidence, quoting real values from the resource config. */
      detail: string;
      /**
       * Distinguishes multiple findings produced by the same rule against the
       * same resource, e.g. `"tcp/22:ipv4"`. Becomes part of the finding's
       * stable id, so it must be derived from the configuration itself and not
       * from an array index — a rule reordering its output must not renumber
       * every existing finding.
       */
      key?: string;
      /**
       * Overrides the rule's default title for this one verdict. Used where a
       * single rule covers a family of related problems and the specific one
       * belongs in the headline, e.g. naming the exact port a security group
       * left open.
       */
      title?: string;
      /**
       * Overrides the rule's default severity. Used sparingly — only where the
       * same rule covers conditions of genuinely different weight.
       */
      severity?: Severity;
    }
  | {
      /**
       * The rule could not reach a verdict, because the data it needs was not
       * observed. Reported, never treated as a pass.
       */
      status: "inconclusive";
      /** Which observation was missing, and what that prevents concluding. */
      detail: string;
      key?: string;
    };

/**
 * Builds the standard "this could not be checked" verdict.
 *
 * Every rule needs this exact shape whenever the field it depends on appears in
 * the resource's `unobserved` list, and the wording matters: the message has to
 * name both the observation that was missed and the conclusion that is
 * therefore unavailable. Generated from one place so that all twelve rules
 * phrase it identically and none of them quietly shortens it to something
 * vaguer over time.
 *
 * @param field - the `config` field the collector could not read, spelled
 *   exactly as it appears in `unobserved`.
 * @param consequence - what cannot be concluded, phrased to follow "so ...",
 *   e.g. `"it cannot tell whether public access is blocked"`.
 */
export function unobservedVerdict(
  field: string,
  consequence: string,
): RuleVerdict {
  return {
    status: "inconclusive",
    detail:
      `The collector could not read "${field}" for this resource, so ${consequence}. ` +
      "Re-run the collector and check the reported collection errors.",
  };
}

// ---------------------------------------------------------------------------
// What a rule is
// ---------------------------------------------------------------------------

/**
 * One compliance check.
 *
 * A rule is a plain object, not a class: it holds no state, performs no I/O,
 * and its `evaluate` is a pure function of the resource handed to it. That is
 * what lets the whole engine run against a committed JSON fixture with no
 * LocalStack, no Docker, and no credentials — the property that makes these
 * checks testable in CI.
 *
 * The generic parameter ties `appliesTo` to the argument type of `evaluate`:
 * a rule declaring `appliesTo: "s3_bucket"` receives a {@link Resource}
 * already narrowed to the S3 variant, so `resource.config.versioning` is
 * type-checked and a typo is a compile error rather than a silent `undefined`
 * that makes the rule quietly never fire.
 *
 * @typeParam T - the resource type this rule inspects.
 */
export interface Rule<T extends ResourceType = ResourceType> {
  /**
   * Stable machine identifier, e.g. `"s3-block-public-access"`.
   *
   * Written into every finding this rule produces and used as part of the
   * finding's primary key, so renaming one is a data migration rather than a
   * cosmetic change. Kebab-case, prefixed with the service.
   */
  id: string;

  /** Default headline for findings from this rule. A verdict may override it. */
  title: string;

  /** Why this matters, in one or two sentences aimed at whoever has to fix it. */
  description: string;

  /** Default severity. A verdict may override it. */
  severity: Severity;

  /**
   * Benchmark control this implements, e.g.
   * `"CIS AWS Foundations v3.0.0 1.16"`. Checks with no direct benchmark
   * equivalent use a `"CloudSentinel"`-prefixed string, so a reader can always
   * tell which checks are standards-backed and which are this project's own
   * additions.
   */
  benchmark: string;

  /** Concrete fix instructions, ideally the exact CLI command that closes it. */
  remediation: string;

  /** Which resource type this rule inspects. The engine skips everything else. */
  appliesTo: T;

  /**
   * Evaluates one resource.
   *
   * Must be pure and must not throw: the engine runs every rule over every
   * resource, and one rule crashing on an unusual config would take the whole
   * scan down with it. Where input might be malformed, return an
   * `inconclusive` verdict instead of throwing.
   *
   * @param resource - the resource to check, narrowed to this rule's type.
   * @returns zero or more verdicts. An empty array means the rule did not
   *   apply to this resource at all (as opposed to `[{ status: "pass" }]`,
   *   which means it applied and the resource is compliant). The distinction
   *   keeps the pass counts honest: an MFA rule should not claim to have
   *   cleared a user who has no console password to protect in the first place.
   */
  evaluate(resource: Extract<Resource, { type: T }>): RuleVerdict[];
}

/**
 * Any rule, regardless of the resource type it targets.
 *
 * A union of the three concrete instantiations rather than `Rule<ResourceType>`:
 * the latter would claim each rule can handle *every* resource type, which is
 * exactly backwards. The engine narrows back to a specific rule by comparing
 * `rule.appliesTo` with `resource.type`.
 */
export type AnyRule =
  | Rule<"s3_bucket">
  | Rule<"security_group">
  | Rule<"iam_user">;

// ---------------------------------------------------------------------------
// What the engine produces
// ---------------------------------------------------------------------------

/** A finding's state. Mirrors the non-passing {@link RuleVerdict} statuses. */
export type FindingStatus = "fail" | "inconclusive";

/**
 * One recorded problem: a rule, a resource, and the evidence that links them.
 *
 * This is the record the dashboard renders and the `findings` table will store,
 * so it is intentionally self-contained. It repeats the rule's severity and
 * remediation rather than referencing the rule by id alone, because a finding
 * needs to stay readable after it has been exported to JSON, stored for a
 * month, or opened by someone who does not have the rule source in front of
 * them.
 */
export interface Finding {
  /**
   * Deterministic identifier: rule id, resource id, and the verdict key.
   *
   * Deterministic rather than random so that re-scanning an unchanged
   * environment produces the same ids. That is what will let the dashboard
   * track a finding's lifecycle — first seen, triaged, resolved — instead of
   * generating a brand new "problem" on every scan and losing all triage state.
   */
  id: string;

  ruleId: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  benchmark: string;
  remediation: string;

  /** Stable id of the offending resource (ARN, or `sg-...` where no ARN exists). */
  resourceId: string;
  resourceName: string;
  resourceType: ResourceType;
  region: string;

  /** Observed evidence from the verdict — real values, not a restatement of the rule. */
  detail: string;

  /**
   * When the underlying scan was taken (ISO-8601), copied from the inventory
   * rather than generated here.
   *
   * A finding's timestamp must describe when the environment was *observed*,
   * not when the rules happened to run over a saved snapshot. Re-running the
   * engine against last week's inventory must not make last week's problems
   * look like today's.
   */
  detectedAt: string;
}

/** Per-rule tally, so the report can show what was checked and not only what failed. */
export interface RuleSummary {
  ruleId: string;
  title: string;
  severity: Severity;
  /** Resources this rule actually evaluated (excludes ones it did not apply to). */
  evaluated: number;
  passed: number;
  failed: number;
  inconclusive: number;
}

/**
 * The complete output of one rule-engine run.
 *
 * Carries the inventory's provenance (`collectedAt`, `endpoint`, `region`)
 * forward so a findings file is self-describing: reading one is enough to know
 * which environment it came from and when. A findings report that cannot say
 * what it was looking at is not evidence of anything.
 */
export interface ScanResult {
  /** When the rules ran (ISO-8601). Distinct from `collectedAt`. */
  scannedAt: string;
  /** When the inventory was collected (ISO-8601). */
  collectedAt: string;
  endpoint: string;
  region: string;

  /** Every non-passing verdict, sorted most severe first. */
  findings: Finding[];
  /** One entry per rule that evaluated at least one resource. */
  ruleSummaries: RuleSummary[];

  /** How many resources the engine looked at, and how many produced no findings at all. */
  resourcesScanned: number;
  resourcesClean: number;

  /**
   * Aggregate risk score, 0 (clean) to 100 (worst).
   *
   * A convenience for the dashboard's headline number. It is a heuristic, not a
   * measurement — see `computeRiskScore` in lib/rules/engine.ts for how it is
   * derived and what it deliberately does not claim.
   */
  riskScore: number;

  /**
   * Collection errors carried over from the inventory.
   *
   * Copied forward so that a report showing zero findings also shows whether
   * the scan could actually see the whole environment. "No findings" from a
   * scan that failed halfway is not a clean bill of health, and the two must
   * never look identical in the output.
   */
  collectionErrors: number;
}
