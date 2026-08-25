/**
 * CloudSentinel — S3 compliance rules.
 *
 * Six CIS-style checks over the {@link S3BucketResource} shape produced by
 * lib/collectors/s3.ts. Exported as {@link S3_RULES} and registered in
 * lib/rules/engine.ts.
 *
 * Where it sits in the architecture: stage two of the pipeline. Nothing here
 * touches AWS — every rule is a pure function of an already-collected resource,
 * which is what lets `npm test` exercise all six against the committed
 * `fixtures/inventory.json` with no LocalStack running.
 *
 *   S3BucketResource --> [ these rules ] --> RuleVerdict[] --> Finding[]
 *
 * The four checks that matter most are the ones about *public* access, and they
 * exist as four separate rules rather than one "bucket is public" rule for a
 * reason worth stating: S3 has four independent mechanisms that can expose a
 * bucket — Block Public Access, the bucket policy, the bucket ACL, and object
 * ACLs — and they override each other in a specific order. Turning off a public
 * bucket policy while leaving a public ACL in place fixes nothing. Reporting
 * them separately means each exposure path gets closed explicitly instead of
 * one finding disappearing while the bucket stays readable.
 *
 * Every rule consults the resource's `unobserved` list before drawing a
 * conclusion. That is the contract set out in lib/types/resource.ts: a `null`
 * field can mean "AWS says this is not configured" (a fact, usually the finding
 * itself) or "the call to find out failed" (no information at all), and the
 * only honest answer in the second case is *inconclusive*.
 */

import type { BucketAclGrant, S3BucketResource } from "../types/resource.ts";
import {
  describeStatement,
  findPublicStatements,
  findUnevaluatableStatements,
  statementKey,
} from "./policy.ts";
import { unobservedVerdict } from "./types.ts";
import type { Rule, RuleVerdict } from "./types.ts";

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/**
 * The two ACL grantee groups that make a bucket effectively public, keyed by
 * the URI AWS uses to identify them.
 *
 * `AllUsers` is literally anyone on the internet with no credentials.
 * `AuthenticatedUsers` sounds restrictive and is not — it means any principal
 * holding *any* AWS account, and anyone can create one in minutes. Both are
 * treated as public exposure, because in practice they are.
 */
const PUBLIC_ACL_GROUPS: Record<string, string> = {
  "http://acs.amazonaws.com/groups/global/AllUsers": "AllUsers",
  "http://acs.amazonaws.com/groups/global/AuthenticatedUsers":
    "AuthenticatedUsers",
};

/**
 * Returns the friendly name of the public group a grant targets, or null when
 * the grant is not public.
 *
 * Matching is on the grantee URI rather than the display name because the URI
 * is the stable identifier AWS guarantees; display names are frequently null in
 * API responses, including LocalStack's.
 */
function publicAclGroup(grant: BucketAclGrant): string | null {
  if (grant.granteeType !== "Group") return null;
  return PUBLIC_ACL_GROUPS[grant.granteeId ?? ""] ?? null;
}

// ---------------------------------------------------------------------------
// Rule: Block Public Access
// ---------------------------------------------------------------------------

/**
 * Flags buckets whose Block Public Access (BPA) settings do not fully protect
 * them.
 *
 * BPA is the account/bucket-level master switch that overrides both ACLs and
 * bucket policies, which makes it the single most valuable S3 control: with all
 * four flags on, a bucket cannot be made public by accident even if someone
 * later attaches a public policy. That is also why disabling it is the *first*
 * step in exposing a bucket — S3 rejects a public bucket policy outright while
 * BPA is on, which is exactly why scripts/seed-localstack.ts has to turn all
 * four flags off before it can attach the public policy on the fixture bucket.
 *
 * Two distinct failure shapes are reported through this one rule:
 *
 *   - No BPA configuration at all (`publicAccessBlock === null`). AWS returns
 *     404 from `GetPublicAccessBlock` in this case. It is *not* a safe default:
 *     nothing is blocking public ACLs or policies.
 *   - Some flags on, some off. Reported separately with its own title, because
 *     a partially-protected bucket is a genuinely different situation from an
 *     unprotected one and lumping them together would hide which flags are left
 *     to fix.
 */
export const blockPublicAccessRule: Rule<"s3_bucket"> = {
  id: "s3-block-public-access",
  title: "S3 bucket has Block Public Access fully disabled",
  description:
    "S3 Block Public Access overrides both ACLs and bucket policies, so with " +
    "all four settings enabled a bucket cannot be exposed by a later " +
    "misconfiguration. Disabling it removes that safety net entirely.",
  severity: "critical",
  benchmark: "CIS AWS Foundations v3.0.0 2.1.4",
  remediation:
    "Enable all four settings: aws s3api put-public-access-block --bucket " +
    "<name> --public-access-block-configuration " +
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true," +
    "RestrictPublicBuckets=true",
  appliesTo: "s3_bucket",

  evaluate(bucket: S3BucketResource): RuleVerdict[] {
    if (bucket.unobserved.includes("publicAccessBlock")) {
      return [
        unobservedVerdict(
          "publicAccessBlock",
          "it cannot tell whether public access is blocked",
        ),
      ];
    }

    const block = bucket.config.publicAccessBlock;
    if (block === null) {
      return [
        {
          status: "fail",
          detail:
            "The bucket has no public access block configuration at all " +
            "(GetPublicAccessBlock returned NoSuchPublicAccessBlockConfiguration). " +
            "Nothing prevents a public ACL or bucket policy from taking effect.",
        },
      ];
    }

    const flags = {
      BlockPublicAcls: block.blockPublicAcls,
      IgnorePublicAcls: block.ignorePublicAcls,
      BlockPublicPolicy: block.blockPublicPolicy,
      RestrictPublicBuckets: block.restrictPublicBuckets,
    };
    const disabled = Object.entries(flags)
      .filter(([, enabled]) => !enabled)
      .map(([name]) => name);

    if (disabled.length === 0) return [{ status: "pass" }];

    if (disabled.length === 4) {
      return [
        {
          status: "fail",
          detail:
            "All four Block Public Access settings are false: " +
            "BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, " +
            "RestrictPublicBuckets.",
        },
      ];
    }

    // Partial protection still leaves a real exposure path open, but it is a
    // smaller one and naming the specific flags is what makes it fixable.
    return [
      {
        status: "fail",
        title: "S3 bucket has Block Public Access partially disabled",
        severity: "high",
        key: "partial",
        detail: `Disabled settings: ${disabled.join(", ")}. Remaining enabled: ${
          4 - disabled.length
        }/4.`,
      },
    ];
  },
};

// ---------------------------------------------------------------------------
// Rule: public bucket policy
// ---------------------------------------------------------------------------

/**
 * Flags bucket policies that grant access to an anonymous or arbitrary
 * principal.
 *
 * This is the classic "leaky S3 bucket" that turns up in breach write-ups: a
 * single statement with `Principal: "*"` and no condition makes every object in
 * the bucket downloadable by anyone who learns the URL, with no credentials and
 * no log of who took what unless access logging happens to be on.
 *
 * One finding is emitted per offending statement rather than one per bucket, so
 * a policy that is public in two different ways produces two things to fix and
 * closing one of them does not mark the other resolved. Statements guarded by a
 * `Condition` are not flagged — see `hasCondition` in lib/rules/policy.ts for
 * that trade-off — and statements using `NotAction`/`NotPrincipal` are reported
 * as inconclusive because CloudSentinel cannot evaluate them.
 */
export const publicBucketPolicyRule: Rule<"s3_bucket"> = {
  id: "s3-public-bucket-policy",
  title: "S3 bucket policy grants access to Principal '*'",
  description:
    "A bucket policy statement with Principal '*' and no condition grants " +
    "anonymous access to anyone on the internet.",
  severity: "critical",
  benchmark: "AWS Foundational Security Best Practices S3.2",
  remediation:
    "Remove or scope the public statement: aws s3api delete-bucket-policy " +
    "--bucket <name>, or replace Principal '*' with the specific accounts, " +
    "roles, or VPC endpoint that need access.",
  appliesTo: "s3_bucket",

  evaluate(bucket: S3BucketResource): RuleVerdict[] {
    if (bucket.unobserved.includes("policy")) {
      return [
        unobservedVerdict(
          "policy",
          "it cannot tell whether the bucket policy grants public access",
        ),
      ];
    }

    const { policy } = bucket.config;
    // A bucket with no policy is the normal, safe case — AWS returns
    // NoSuchBucketPolicy, which the collector records as null without marking
    // the field unobserved. The check above is what separates that from a
    // policy nobody managed to read.
    if (policy === null) return [{ status: "pass" }];

    const verdicts: RuleVerdict[] = [];

    // The actions worth reporting on, most severe first. Checked individually
    // rather than as "any public statement" so the finding names the actual
    // capability granted — "anyone can delete your objects" and "anyone can
    // read them" call for very different urgency.
    const SENSITIVE_ACTIONS = [
      "s3:DeleteObject",
      "s3:PutObject",
      "s3:GetObject",
      "s3:ListBucket",
    ];

    // Deduplicated by statement, because one statement granting several public
    // actions is one thing to fix, not four.
    const reported = new Set<string>();
    for (const action of SENSITIVE_ACTIONS) {
      for (const statement of findPublicStatements(policy, action)) {
        const key = statementKey(statement);
        if (reported.has(key)) continue;
        reported.add(key);

        // The title names the concrete action rather than the wildcard the
        // policy may have used, so a reader sees the capability, not the
        // syntax. A policy saying Action "s3:*" surfaces as the most severe
        // action it actually confers.
        verdicts.push({
          status: "fail",
          key,
          title: `S3 bucket policy grants ${action} to Principal '*'`,
          detail: describeStatement(statement),
        });
      }
    }

    for (const statement of findUnevaluatableStatements(policy)) {
      verdicts.push({
        status: "inconclusive",
        key: `unevaluatable:${statementKey(statement)}`,
        detail:
          "Statement uses NotAction/NotResource/NotPrincipal, which " +
          "CloudSentinel does not evaluate — it may be broader than it looks. " +
          `Review it by hand: ${describeStatement(statement)}`,
      });
    }

    // A policy that exists but grants nothing public is a genuine pass, and
    // saying so is worth more than silence: it records that the policy was
    // read and understood.
    return verdicts.length > 0 ? verdicts : [{ status: "pass" }];
  },
};

// ---------------------------------------------------------------------------
// Rule: public bucket ACL
// ---------------------------------------------------------------------------

/**
 * Flags bucket ACLs that grant a permission to `AllUsers` or
 * `AuthenticatedUsers`.
 *
 * ACLs are S3's legacy access-control mechanism, predating bucket policies, and
 * they are easy to miss in an audit precisely because most attention goes to
 * the policy. A single `READ` grant to `AllUsers` makes the bucket listable by
 * anyone regardless of how carefully the bucket policy is written, and AWS's
 * own console does not show it on the same screen as the policy.
 *
 * `WRITE` and `FULL_CONTROL` grants are escalated to reflect what they actually
 * permit: an anonymous writer can upload objects (hosting malware under the
 * bucket's name, or running up its bill) and `WRITE_ACP` lets them rewrite the
 * ACL itself to lock the owner out.
 */
export const publicBucketAclRule: Rule<"s3_bucket"> = {
  id: "s3-public-bucket-acl",
  title: "S3 bucket ACL grants access to a public group",
  description:
    "Bucket ACL grants to the AllUsers or AuthenticatedUsers groups expose " +
    "the bucket independently of its bucket policy.",
  severity: "critical",
  benchmark: "AWS Foundational Security Best Practices S3.2",
  remediation:
    "Remove the public grant: aws s3api put-bucket-acl --bucket <name> " +
    "--acl private, and prefer bucket policies over ACLs by setting the " +
    "bucket's object ownership to BucketOwnerEnforced, which disables ACLs " +
    "entirely.",
  appliesTo: "s3_bucket",

  evaluate(bucket: S3BucketResource): RuleVerdict[] {
    if (bucket.unobserved.includes("aclGrants")) {
      return [
        unobservedVerdict("aclGrants", "it cannot tell whether the ACL is public"),
      ];
    }

    const verdicts: RuleVerdict[] = [];
    for (const grant of bucket.config.aclGrants) {
      const group = publicAclGroup(grant);
      if (group === null) continue;

      // WRITE-family grants let an anonymous party change the bucket's
      // contents or its ACL, which is materially worse than being able to
      // read it — but every one of these is already critical, so the
      // distinction lives in the detail text rather than in the severity.
      const writeable =
        grant.permission === "WRITE" ||
        grant.permission === "WRITE_ACP" ||
        grant.permission === "FULL_CONTROL";

      verdicts.push({
        status: "fail",
        key: `${group}:${grant.permission}`,
        title: `S3 bucket ACL grants ${grant.permission} to ${group}`,
        detail:
          `ACL grant: ${grant.permission} to the ${group} group ` +
          `(${grant.granteeId}).` +
          (writeable
            ? " This permits anonymous modification of the bucket or its ACL."
            : " This permits anonymous read access to the bucket's contents."),
      });
    }

    return verdicts.length > 0 ? verdicts : [{ status: "pass" }];
  },
};

// ---------------------------------------------------------------------------
// Rule: versioning
// ---------------------------------------------------------------------------

/**
 * Flags buckets without object versioning enabled.
 *
 * Versioning is a recovery control rather than a preventive one, which is why
 * it is `medium` and not `critical`: it does not stop an attacker getting in,
 * but without it a single `DeleteObject` or an overwrite by ransomware is
 * unrecoverable. It is also a prerequisite for MFA Delete, the control that
 * stops a compromised credential from permanently destroying data.
 *
 * `Suspended` is reported under its own title. It means versioning was enabled
 * at some point, so older object versions may still exist and still cost money,
 * while new writes are no longer protected — a distinct state from a bucket
 * that never had versioning at all.
 */
export const versioningDisabledRule: Rule<"s3_bucket"> = {
  id: "s3-versioning-disabled",
  title: "S3 bucket has versioning disabled",
  description:
    "Without versioning, an overwritten or deleted object cannot be " +
    "recovered, and MFA Delete cannot be enabled.",
  severity: "medium",
  benchmark: "AWS Foundational Security Best Practices S3.14",
  remediation:
    "aws s3api put-bucket-versioning --bucket <name> " +
    "--versioning-configuration Status=Enabled",
  appliesTo: "s3_bucket",

  evaluate(bucket: S3BucketResource): RuleVerdict[] {
    if (bucket.unobserved.includes("versioning")) {
      return [
        unobservedVerdict("versioning", "it cannot tell whether versioning is on"),
      ];
    }

    switch (bucket.config.versioning) {
      case "Enabled":
        return [{ status: "pass" }];
      case "Suspended":
        return [
          {
            status: "fail",
            key: "suspended",
            title: "S3 bucket has versioning suspended",
            detail:
              "Versioning status is Suspended: existing object versions are " +
              "retained, but new writes and deletes are no longer versioned.",
          },
        ];
      case "Disabled":
        return [
          {
            status: "fail",
            detail:
              "Versioning has never been enabled on this bucket, so " +
              "overwritten or deleted objects cannot be recovered.",
          },
        ];
    }
  },
};

// ---------------------------------------------------------------------------
// Rule: server access logging
// ---------------------------------------------------------------------------

/**
 * Flags buckets with no server access logging.
 *
 * This is the check that decides whether a future incident can be investigated
 * at all. If the public bucket in the fixtures were real and its contents
 * turned up online, access logs are the only record of which objects were
 * fetched and from where — and they cannot be turned on retroactively. That is
 * why a missing log is worth reporting even though it exposes nothing by
 * itself: the cost of the gap is paid later, at the worst possible moment.
 */
export const accessLoggingDisabledRule: Rule<"s3_bucket"> = {
  id: "s3-access-logging-disabled",
  title: "S3 bucket has no server access logging",
  description:
    "Without server access logging there is no record of who read from or " +
    "wrote to the bucket, so a leak cannot be investigated after the fact.",
  severity: "medium",
  benchmark: "AWS Foundational Security Best Practices S3.9",
  remediation:
    "aws s3api put-bucket-logging --bucket <name> --bucket-logging-status " +
    '\'{"LoggingEnabled":{"TargetBucket":"<log-bucket>","TargetPrefix":"<name>/"}}\'',
  appliesTo: "s3_bucket",

  evaluate(bucket: S3BucketResource): RuleVerdict[] {
    if (bucket.unobserved.includes("loggingEnabled")) {
      return [
        unobservedVerdict("loggingEnabled", "it cannot tell whether logging is on"),
      ];
    }

    if (!bucket.config.loggingEnabled) {
      return [
        {
          status: "fail",
          detail:
            "GetBucketLogging returned no LoggingEnabled block: access to " +
            "this bucket is not being recorded anywhere.",
        },
      ];
    }

    return [{ status: "pass" }];
  },
};

// ---------------------------------------------------------------------------
// Rule: default encryption
// ---------------------------------------------------------------------------

/**
 * Flags buckets with no default server-side encryption rule.
 *
 * Included even though the seeded fixtures do not currently trigger it —
 * LocalStack applies AES256 by default, as does real S3 since January 2023 —
 * because a rule that passes is still doing work: it records that the setting
 * was checked, and it will fire on any bucket where someone has explicitly
 * removed the encryption configuration.
 *
 * Severity is `low` deliberately. Default SSE protects against one specific
 * threat, physical access to AWS's disks, and does nothing against the
 * misconfigurations the other rules in this file detect. Rating it higher would
 * put a largely theoretical risk next to a world-readable bucket in the same
 * report, which is how a dashboard stops being useful.
 */
export const defaultEncryptionRule: Rule<"s3_bucket"> = {
  id: "s3-default-encryption-disabled",
  title: "S3 bucket has no default encryption configured",
  description:
    "Default server-side encryption ensures every object written to the " +
    "bucket is encrypted at rest without the writer having to ask for it.",
  severity: "low",
  benchmark: "AWS Foundational Security Best Practices S3.4",
  remediation:
    "aws s3api put-bucket-encryption --bucket <name> " +
    "--server-side-encryption-configuration " +
    '\'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}\'',
  appliesTo: "s3_bucket",

  evaluate(bucket: S3BucketResource): RuleVerdict[] {
    if (bucket.unobserved.includes("encryptionAlgorithm")) {
      return [
        unobservedVerdict(
          "encryptionAlgorithm",
          "it cannot tell whether default encryption is configured",
        ),
      ];
    }

    if (bucket.config.encryptionAlgorithm === null) {
      return [
        {
          status: "fail",
          detail:
            "GetBucketEncryption returned no default encryption rule, so " +
            "objects written without an explicit SSE header are stored " +
            "unencrypted.",
        },
      ];
    }

    return [{ status: "pass" }];
  },
};

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/**
 * Every S3 rule, in the order they should be evaluated and displayed.
 *
 * Ordered by exposure path first (the three public-access rules), then by
 * durability and forensics, then by hygiene — so reading a bucket's findings
 * top to bottom tells the story of how exposed it is before it gets to what is
 * merely untidy.
 */
export const S3_RULES: readonly Rule<"s3_bucket">[] = [
  blockPublicAccessRule,
  publicBucketPolicyRule,
  publicBucketAclRule,
  versioningDisabledRule,
  accessLoggingDisabledRule,
  defaultEncryptionRule,
];
