/**
 * CloudSentinel — IAM compliance rules.
 *
 * Five checks over the {@link IamUserResource} shape produced by
 * lib/collectors/iam.ts. Exported as {@link IAM_RULES} and registered in
 * lib/rules/engine.ts.
 *
 * Where it sits in the architecture: stage two of the pipeline, alongside
 * lib/rules/s3.ts and lib/rules/ec2.ts. Pure functions over already-collected
 * data — no AWS SDK, no network, no credentials.
 *
 *   IamUserResource --> [ these rules ] --> RuleVerdict[] --> Finding[]
 *
 * IAM is where a cloud audit is easiest to get wrong, for one structural
 * reason: a principal's permissions are the *union* of four separate sources —
 * policies attached to the user, policies written inline on the user, policies
 * attached to each of the user's groups, and policies written inline on those
 * groups. A user object with an empty `AttachedPolicies` list can still be a
 * full account administrator through a single group membership, and a scanner
 * that reads only the user reports that account as clean.
 *
 * That is a *false negative*, and it is the worst kind of error a security tool
 * can make: a false positive wastes someone's afternoon, but a false negative
 * produces a green dashboard that nobody has any reason to question. So the
 * rules below deliberately cover both paths, and group-inherited administrative
 * access is reported under its own rule id and its own headline rather than
 * being folded into the direct one — because "this user is an admin" and "this
 * group makes everyone in it an admin" have completely different fixes. The
 * second one is usually a much bigger problem, since it applies to every
 * current and future member of the group.
 *
 * SECURITY: nothing in this file ever handles a secret. The collector records
 * access key *metadata* only (id, status, age) and never the secret, which is
 * unretrievable after creation in any case — see lib/types/resource.ts. Access
 * key ids do appear in finding details, which is intended: an id is a public
 * identifier, it is what `aws iam delete-access-key` needs, and a finding that
 * says "rotate one of this user's keys" without saying which one is not
 * actionable.
 */

import type {
  AttachedPolicySummary,
  IamUserConfig,
  IamUserResource,
  InlinePolicySummary,
} from "../types/resource.ts";
import {
  describeStatement,
  findAdminStatements,
  findUnrestrictedActionStatements,
  statementKey,
} from "./policy.ts";
import { unobservedVerdict } from "./types.ts";
import type { Rule, RuleVerdict } from "./types.ts";

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/**
 * A policy paired with where it came from, so a finding can say
 * "attached policy CloudSentinelWildcardAccess" or "inline policy X on group Y"
 * rather than just naming a document.
 *
 * Provenance is not cosmetic here. Removing an over-broad *attached* policy is
 * a one-line detach; removing the same permissions granted *inline on a group*
 * means editing the group and affecting everyone in it. The reader needs to
 * know which situation they are in before they can act.
 */
interface SourcedPolicy {
  /** Human-readable origin, e.g. `'attached policy "AdministratorAccess"'`. */
  source: string;
  /** Short stable fragment for the finding key, e.g. `"attached:AdminAccess"`. */
  keyPrefix: string;
  policyName: string;
  /** Parsed document, or null when the collector could not fetch it. */
  document: AttachedPolicySummary["document"];
}

/** Flattens a user's directly-attached managed policies into {@link SourcedPolicy}. */
function directAttached(config: IamUserConfig): SourcedPolicy[] {
  return config.attachedPolicies.map((policy: AttachedPolicySummary) => ({
    source: `attached policy "${policy.policyName}" (${policy.policyArn})`,
    keyPrefix: `attached:${policy.policyName}`,
    policyName: policy.policyName,
    document: policy.document,
  }));
}

/** Flattens a user's inline policies into {@link SourcedPolicy}. */
function directInline(config: IamUserConfig): SourcedPolicy[] {
  return config.inlinePolicies.map((policy: InlinePolicySummary) => ({
    source: `inline policy "${policy.policyName}"`,
    keyPrefix: `inline:${policy.policyName}`,
    policyName: policy.policyName,
    document: policy.document,
  }));
}

/**
 * Flattens every policy the user inherits through group membership.
 *
 * This is the path that makes the difference between an audit that works and
 * one that quietly misses administrators. See the file header.
 */
function viaGroups(config: IamUserConfig): SourcedPolicy[] {
  return config.groups.flatMap((group) => [
    ...group.attachedPolicies.map((policy) => ({
      source: `attached policy "${policy.policyName}" on group "${group.groupName}"`,
      keyPrefix: `group:${group.groupName}:attached:${policy.policyName}`,
      policyName: policy.policyName,
      document: policy.document,
    })),
    ...group.inlinePolicies.map((policy) => ({
      source: `inline policy "${policy.policyName}" on group "${group.groupName}"`,
      keyPrefix: `group:${group.groupName}:inline:${policy.policyName}`,
      policyName: policy.policyName,
      document: policy.document,
    })),
  ]);
}

/**
 * Builds the inconclusive verdict for a policy whose document could not be
 * fetched.
 *
 * An unread policy is not a harmless policy. `GetPolicyVersion` can be denied
 * by the very permissions boundary being audited, and the document nobody could
 * read is exactly the one most likely to be interesting. Reporting this as a
 * gap keeps the scan honest instead of letting a permissions error masquerade
 * as a clean result.
 */
function unreadablePolicy(policy: SourcedPolicy): RuleVerdict {
  return {
    status: "inconclusive",
    key: `unreadable:${policy.keyPrefix}`,
    detail:
      `The document for ${policy.source} could not be retrieved, so its ` +
      "permissions were not evaluated. Check the collection errors from the " +
      "most recent scan.",
  };
}

// ---------------------------------------------------------------------------
// Rule: directly-granted administrative access
// ---------------------------------------------------------------------------

/**
 * Flags users holding a policy that grants `Action: "*"` on `Resource: "*"`
 * directly, whether attached or inline.
 *
 * This is the shape that makes a principal equivalent to the account root for
 * everything except billing: it can read every bucket, delete every snapshot,
 * create new administrators, and — most importantly — disable CloudTrail and
 * erase the evidence. Any single credential belonging to such a user is a total
 * account compromise if it leaks, which is why this is `critical` rather than
 * merely `high`.
 *
 * Statements carrying a `Condition` are not flagged; see `hasCondition` in
 * lib/rules/policy.ts for that trade-off, which exists so a properly-guarded
 * break-glass role does not generate noise.
 */
export const adminPolicyAttachedRule: Rule<"iam_user"> = {
  id: "iam-admin-policy-direct",
  title: "IAM user has a policy with Action '*' on Resource '*'",
  description:
    "A policy allowing every action on every resource makes the user " +
    "equivalent to the account root, including the ability to disable " +
    "logging and create further administrators.",
  severity: "critical",
  benchmark: "CIS AWS Foundations v3.0.0 1.16",
  remediation:
    "Detach the policy and replace it with one scoped to the actions and " +
    "resources the user actually needs: aws iam detach-user-policy " +
    "--user-name <user> --policy-arn <arn>. Use IAM Access Analyzer's " +
    "policy generation from CloudTrail history to derive the minimum set.",
  appliesTo: "iam_user",

  evaluate(user: IamUserResource): RuleVerdict[] {
    const missing = ["attachedPolicies", "inlinePolicies"].filter((field) =>
      user.unobserved.includes(field),
    );
    if (missing.length > 0) {
      return [
        unobservedVerdict(
          missing.join('", "'),
          "it cannot tell what permissions are granted directly to this user",
        ),
      ];
    }

    const verdicts: RuleVerdict[] = [];

    for (const policy of [...directAttached(user.config), ...directInline(user.config)]) {
      if (policy.document === null) {
        verdicts.push(unreadablePolicy(policy));
        continue;
      }

      for (const statement of findAdminStatements(policy.document)) {
        // The headline distinguishes attached from inline because the fix
        // differs: an attached policy is detached, an inline one is deleted or
        // rewritten in place.
        const kind = policy.keyPrefix.startsWith("attached:")
          ? "an attached policy"
          : "an inline policy";

        verdicts.push({
          status: "fail",
          key: `${policy.keyPrefix}:${statementKey(statement)}`,
          title: `IAM user has ${kind} with Action '*' on Resource '*'`,
          detail: `${policy.source}: ${describeStatement(statement)}`,
        });
      }
    }

    return verdicts.length > 0 ? verdicts : [{ status: "pass" }];
  },
};

// ---------------------------------------------------------------------------
// Rule: administrative access inherited through a group
// ---------------------------------------------------------------------------

/**
 * Flags users who are administrators only because of a group they belong to.
 *
 * Kept separate from {@link adminPolicyAttachedRule} on purpose. A user with a
 * directly-attached admin policy is one over-privileged account; a group that
 * grants admin is an over-privileged *class* of account, and it silently
 * promotes every future member the moment they are added. Fixing the group is
 * also a different and riskier operation than fixing one user, because it
 * affects everyone in it at once.
 *
 * This is the check that the seeded `cloudsentinel-group-member` fixture exists
 * to exercise: that user has no attached policies, no inline policies, no
 * access keys, and no console password. Every user-level field says "harmless".
 * Only resolving the group's policies reveals a full administrator.
 */
export const adminViaGroupRule: Rule<"iam_user"> = {
  id: "iam-admin-policy-via-group",
  title: "IAM user inherits Action '*' on Resource '*' through group membership",
  description:
    "The user has no direct administrative policy, but a group they belong " +
    "to grants every action on every resource — so the user is a full " +
    "administrator, and so is every other member of that group.",
  severity: "critical",
  benchmark: "CIS AWS Foundations v3.0.0 1.16",
  remediation:
    "Fix the group rather than the user: aws iam detach-group-policy " +
    "--group-name <group> --policy-arn <arn>. Verify who else is affected " +
    "first with aws iam get-group --group-name <group>.",
  appliesTo: "iam_user",

  evaluate(user: IamUserResource): RuleVerdict[] {
    // "groups" covers the membership list and "groupNames" the lookup that
    // produces it; either being unobserved means group-derived permissions
    // were not fully resolved, and the whole point of this rule is that an
    // unresolved group is where an administrator hides.
    const missing = ["groups", "groupNames"].filter((field) =>
      user.unobserved.includes(field),
    );
    if (missing.length > 0) {
      return [
        unobservedVerdict(
          missing.join('", "'),
          "it cannot tell what permissions this user inherits from groups",
        ),
      ];
    }

    // A user in no groups cannot inherit anything, so the rule does not apply
    // — distinct from applying and passing. Returning an empty array keeps the
    // pass count meaningful: it counts users whose groups were checked and
    // found safe, not users who had no groups to check.
    if (user.config.groups.length === 0) return [];

    const verdicts: RuleVerdict[] = [];

    for (const policy of viaGroups(user.config)) {
      if (policy.document === null) {
        verdicts.push(unreadablePolicy(policy));
        continue;
      }

      for (const statement of findAdminStatements(policy.document)) {
        verdicts.push({
          status: "fail",
          key: `${policy.keyPrefix}:${statementKey(statement)}`,
          detail: `${policy.source}: ${describeStatement(statement)}`,
        });
      }
    }

    return verdicts.length > 0 ? verdicts : [{ status: "pass" }];
  },
};

// ---------------------------------------------------------------------------
// Rule: unrestricted iam:PassRole
// ---------------------------------------------------------------------------

/**
 * Flags policies granting `iam:PassRole` on `Resource: "*"`.
 *
 * `iam:PassRole` is the least obvious entry on this list and one of the most
 * dangerous. It does not grant any permission by itself — it grants the ability
 * to *hand an existing role to an AWS service*. Combined with permission to
 * launch almost anything (an EC2 instance, a Lambda function, a CodeBuild
 * project), an unscoped `PassRole` lets the holder attach the account's most
 * privileged role to a resource they control and then use it. That is a
 * complete privilege escalation from a policy that, at a glance, looks like it
 * grants nothing at all.
 *
 * Scoped correctly — `Resource` naming the specific role ARNs that may be
 * passed — it is ordinary and necessary, which is why the rule fires only on
 * the unrestricted, unconditioned form.
 *
 * A bare `Action: "*"` is deliberately *not* counted here: it technically
 * includes `iam:PassRole`, but it is already reported by
 * {@link adminPolicyAttachedRule} under a headline that describes the far
 * larger problem, and reporting the same policy twice would inflate the finding
 * count without adding anything to fix. A narrower wildcard such as `"iam:*"`
 * does count — that is a genuine, targeted grant of the action.
 *
 * Both direct and group-inherited grants are checked, for the reason set out in
 * the file header.
 */
export const unrestrictedPassRoleRule: Rule<"iam_user"> = {
  id: "iam-unrestricted-passrole",
  title: "IAM user has a policy allowing unrestricted iam:PassRole",
  description:
    "iam:PassRole on Resource '*' lets the holder attach any role in the " +
    "account — including an administrator role — to a service they control, " +
    "which is a complete privilege escalation path.",
  severity: "high",
  benchmark: "CloudSentinel privilege-escalation check (no direct CIS control)",
  remediation:
    "Scope the Resource element to the specific role ARNs that may be " +
    "passed, and add an iam:PassedToService condition naming the service " +
    "allowed to receive them.",
  appliesTo: "iam_user",

  evaluate(user: IamUserResource): RuleVerdict[] {
    const missing = ["attachedPolicies", "inlinePolicies", "groups"].filter(
      (field) => user.unobserved.includes(field),
    );
    if (missing.length > 0) {
      return [
        unobservedVerdict(
          missing.join('", "'),
          "it cannot tell whether this user can pass arbitrary roles",
        ),
      ];
    }

    const verdicts: RuleVerdict[] = [];

    const all = [
      ...directAttached(user.config),
      ...directInline(user.config),
      ...viaGroups(user.config),
    ];

    for (const policy of all) {
      // A document that could not be read is already reported as inconclusive
      // by the admin rules; repeating it here for every rule that reads
      // policies would produce three copies of the same gap. Skipping keeps
      // the report readable — the gap is still surfaced, once.
      if (policy.document === null) continue;

      const statements = findUnrestrictedActionStatements(
        policy.document,
        "iam:PassRole",
        { ignoreBareWildcard: true },
      );

      for (const statement of statements) {
        const inherited = policy.keyPrefix.startsWith("group:");
        const kind = policy.keyPrefix.includes("inline:")
          ? "an inline policy"
          : "an attached policy";

        verdicts.push({
          status: "fail",
          key: `${policy.keyPrefix}:${statementKey(statement)}`,
          title: inherited
            ? "IAM user inherits an unrestricted iam:PassRole grant through group membership"
            : `IAM user has ${kind} allowing unrestricted iam:PassRole`,
          detail: `${policy.source}: ${describeStatement(statement)}`,
        });
      }
    }

    return verdicts.length > 0 ? verdicts : [{ status: "pass" }];
  },
};

// ---------------------------------------------------------------------------
// Rule: console access without MFA
// ---------------------------------------------------------------------------

/**
 * Flags users who can sign in to the AWS console with a password but have no
 * MFA device enrolled.
 *
 * The rule is the *conjunction* of those two facts, and the second half is what
 * keeps it accurate. A service account with programmatic access only has no
 * password to steal, so demanding MFA of it would be a false positive —
 * CloudSentinel's own `cloudsentinel-readonly-svc` fixture is exactly that
 * case, and it must stay clean under this rule. Reporting only on users who
 * actually have a login profile is the difference between a check people act on
 * and a check people filter out.
 *
 * Users without console access return no verdict at all rather than a pass, so
 * the rule's pass count means "console users who do have MFA" rather than being
 * padded with accounts the rule never applied to.
 */
export const consoleWithoutMfaRule: Rule<"iam_user"> = {
  id: "iam-console-without-mfa",
  title: "IAM user has console access but no MFA device",
  description:
    "A console password with no second factor means a single leaked or " +
    "guessed credential is enough to sign in as this user.",
  severity: "high",
  benchmark: "CIS AWS Foundations v3.0.0 1.10",
  remediation:
    "Enrol a virtual MFA device (aws iam create-virtual-mfa-device, then " +
    "aws iam enable-mfa-device), or remove console access entirely if the " +
    "account is only used programmatically: aws iam delete-login-profile " +
    "--user-name <user>.",
  appliesTo: "iam_user",

  evaluate(user: IamUserResource): RuleVerdict[] {
    const missing = ["hasConsoleAccess", "mfaDeviceIds"].filter((field) =>
      user.unobserved.includes(field),
    );
    if (missing.length > 0) {
      return [
        unobservedVerdict(
          missing.join('", "'),
          "it cannot tell whether this user needs MFA or already has it",
        ),
      ];
    }

    if (!user.config.hasConsoleAccess) return [];

    if (user.config.mfaDeviceIds.length === 0) {
      const lastUsed = user.config.passwordLastUsed;
      return [
        {
          status: "fail",
          detail:
            "The user has a login profile (console password) and no MFA " +
            "devices enrolled. Password last used: " +
            `${lastUsed ?? "never"}.`,
        },
      ];
    }

    return [{ status: "pass" }];
  },
};

// ---------------------------------------------------------------------------
// Rule: long-lived access keys
// ---------------------------------------------------------------------------

/**
 * Maximum age, in days, before an access key is considered overdue for
 * rotation.
 *
 * 90 days is the CIS figure. It is a compromise rather than a security
 * boundary: a leaked key is dangerous from the moment it leaks, and rotation
 * only bounds how long the damage lasts.
 */
const MAX_KEY_AGE_DAYS = 90;

/**
 * Flags long-lived static credentials on an IAM user.
 *
 * "Long-lived" covers two conditions, both of which describe a credential that
 * exists for longer than it should:
 *
 *   1. An active key older than {@link MAX_KEY_AGE_DAYS}. This is the CIS
 *      rotation check — the longer a key lives, the more places it has been
 *      copied to and the longer a leaked copy stays valid.
 *   2. An active key on a user who *also* has console access. CIS calls this
 *      out separately, and the reasoning is about intent: a human who signs in
 *      to the console rarely needs a permanent programmatic credential as well,
 *      and one created "just in case" at account setup tends to sit unused and
 *      unrotated in a config file for years. This is the condition the seeded
 *      `cloudsentinel-admin-svc` fixture triggers — its key is brand new, so
 *      the age check alone would not fire, but a freshly-created key on a
 *      console user is precisely the pattern CIS asks to be caught at setup
 *      time rather than 90 days later.
 *
 * Inactive keys are not flagged: they cannot authenticate. They are still worth
 * deleting eventually, but reporting them at the same level as a live
 * credential would be dishonest about the actual risk.
 *
 * A key whose creation date AWS did not return produces an *inconclusive*
 * verdict rather than a pass — its age is unknown, and unknown is not young.
 */
export const longLivedAccessKeyRule: Rule<"iam_user"> = {
  id: "iam-long-lived-access-key",
  title: "IAM user has a long-lived access key",
  description:
    "Static access keys do not expire. A key that is old, or that exists " +
    "alongside console access, is a permanent credential with a wide window " +
    "of exposure.",
  severity: "high",
  benchmark: "CIS AWS Foundations v3.0.0 1.11 / 1.14",
  remediation:
    "Rotate or remove the key: aws iam delete-access-key --user-name <user> " +
    "--access-key-id <id>. Prefer short-lived credentials from an IAM role " +
    "(instance profile, IAM Roles Anywhere, or IAM Identity Center) over " +
    "static keys wherever the workload allows it.",
  appliesTo: "iam_user",

  evaluate(user: IamUserResource): RuleVerdict[] {
    const missing = ["accessKeys", "hasConsoleAccess"].filter((field) =>
      user.unobserved.includes(field),
    );
    if (missing.length > 0) {
      return [
        unobservedVerdict(
          missing.join('", "'),
          "it cannot tell what static credentials this user holds",
        ),
      ];
    }

    const active = user.config.accessKeys.filter(
      (key) => key.status === "Active",
    );
    if (active.length === 0) return [{ status: "pass" }];

    const verdicts: RuleVerdict[] = [];

    for (const key of active) {
      // The key id is a public identifier, not a secret — it is what the
      // remediation command needs. The secret is never collected at all.
      if (key.ageInDays === null) {
        verdicts.push({
          status: "inconclusive",
          key: key.accessKeyId,
          detail:
            `Access key ${key.accessKeyId} is Active but AWS returned no ` +
            "creation date, so its age could not be checked against the " +
            `${MAX_KEY_AGE_DAYS}-day rotation window.`,
        });
        continue;
      }

      if (key.ageInDays > MAX_KEY_AGE_DAYS) {
        verdicts.push({
          status: "fail",
          key: key.accessKeyId,
          detail:
            `Access key ${key.accessKeyId} is Active and ${key.ageInDays} ` +
            `days old, past the ${MAX_KEY_AGE_DAYS}-day rotation window ` +
            `(created ${key.createdAt}).`,
        });
        continue;
      }

      if (user.config.hasConsoleAccess) {
        verdicts.push({
          status: "fail",
          key: key.accessKeyId,
          detail:
            `Access key ${key.accessKeyId} is Active on a user who also has ` +
            "console access. A console user should not hold a permanent " +
            `programmatic credential (key is ${key.ageInDays} days old).`,
        });
      }
    }

    return verdicts.length > 0 ? verdicts : [{ status: "pass" }];
  },
};

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/**
 * Every IAM rule, in evaluation and display order.
 *
 * Ordered by blast radius: what the user can do to the whole account first,
 * then the escalation path, then the authentication weaknesses that let an
 * attacker become the user in the first place.
 */
export const IAM_RULES: readonly Rule<"iam_user">[] = [
  adminPolicyAttachedRule,
  adminViaGroupRule,
  unrestrictedPassRoleRule,
  consoleWithoutMfaRule,
  longLivedAccessKeyRule,
];
