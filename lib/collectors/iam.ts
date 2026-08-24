/**
 * CloudSentinel — IAM user collector.
 *
 * Reads every IAM user in the target account and converts it into the
 * normalized {@link IamUserResource} shape from lib/types/resource.ts.
 *
 * Where it sits in the architecture: stage one of the pipeline, alongside the
 * S3 and EC2 collectors.
 *
 *   LocalStack --> [ collectIamUsers ] --> IamUserResource[] --> rule engine
 *
 * SECURITY: strictly read-only. Only `List*` and `Get*` commands appear here —
 * no `Create*`, `Put*`, `Attach*`, or `Delete*`, and there must never be.
 * scripts/seed-localstack.ts is the only component allowed to change cloud
 * state.
 *
 * SECURITY: access key *secrets* are never collected. AWS only returns a secret
 * once, at creation, and no API can retrieve it afterwards — but the point is
 * that CloudSentinel does not want it. Only key metadata (id, status, age) is
 * needed to reason about key hygiene, so a secret can never reach the database,
 * a log line, or the dashboard. The same applies to console passwords:
 * `GetLoginProfile` is called to learn *whether* a password exists, never what
 * it is.
 *
 * This is the most call-heavy collector. IAM spreads a user's security posture
 * across seven or eight separate APIs, and a user that looks harmless in
 * `ListUsers` can be an administrator through any one of them:
 *
 *   ListUsers                  the users themselves
 *   ListAttachedUserPolicies   managed policies, by ARN only
 *   GetPolicy + GetPolicyVersion   the actual document behind each ARN
 *   ListUserPolicies + GetUserPolicy   inline policies
 *   ListMFADevices             whether MFA is enrolled
 *   ListAccessKeys             long-lived programmatic credentials
 *   ListGroupsForUser          group membership
 *   ListAttachedGroupPolicies + ListGroupPolicies + GetGroupPolicy
 *                              what those groups actually grant
 *   GetLoginProfile            whether the user can sign in to the console
 *   ListUserTags               tags (ListUsers does not return them)
 */

import {
  type AccessKeyMetadata,
  GetGroupPolicyCommand,
  GetLoginProfileCommand,
  GetPolicyCommand,
  GetPolicyVersionCommand,
  GetUserPolicyCommand,
  type IAMClient,
  ListAccessKeysCommand,
  ListAttachedGroupPoliciesCommand,
  ListAttachedUserPoliciesCommand,
  ListGroupPoliciesCommand,
  ListGroupsForUserCommand,
  ListMFADevicesCommand,
  ListUserPoliciesCommand,
  ListUserTagsCommand,
  ListUsersCommand,
  type User,
} from "@aws-sdk/client-iam";

import { createIAMClient } from "../aws/localstack.ts";
import {
  collectorConcurrency,
  mapWithConcurrency,
} from "../util/concurrency.ts";
import type {
  AccessKeySummary,
  AttachedPolicySummary,
  CollectionError,
  GroupMembership,
  IamUserResource,
  InlinePolicySummary,
  PolicyDocument,
} from "../types/resource.ts";

/**
 * What this collector returns: the users it read, plus any non-fatal problems.
 * Same contract as the other two collectors — errors are returned, not thrown.
 */
export interface IamCollectionResult {
  resources: IamUserResource[];
  errors: CollectionError[];
}

/**
 * IAM is a global service with no regional endpoints, so its resources are
 * recorded as `"global"` rather than being filed under whichever region the
 * client happened to be configured with.
 */
const IAM_REGION = "global";

/**
 * An IAM user that AWS actually returned a name and ARN for.
 *
 * Every field on the SDK's `User` type is optional, because the shape is
 * generated from the service model rather than from what the API realistically
 * returns. CloudSentinel cannot do anything useful with a user it cannot name
 * or address, so the list is narrowed to this type up front and the rest of the
 * collector can rely on both fields being present.
 *
 * Written as an intersection with the SDK's `User` rather than as a standalone
 * object type: a type predicate must narrow to something assignable to the
 * value being tested, and a hand-written shape missing `Path`/`UserId` is not.
 */
type IdentifiedUser = User & { UserName: string; Arn: string };

function awsErrorCode(error: unknown): string {
  if (typeof error !== "object" || error === null) return "";
  const candidate = error as { name?: string; Code?: string; code?: string };
  return candidate.name ?? candidate.Code ?? candidate.code ?? "";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Error codes meaning "this thing does not exist", which for IAM is routine
 * rather than exceptional. A user with no console password genuinely has no
 * login profile, and `GetLoginProfile` signals that by throwing.
 */
const NOT_FOUND_CODES = [
  "NoSuchEntity",
  "NoSuchEntityException",
  "NotFoundException",
];

/** Everything {@link optional} needs, as an object for legible call sites. */
interface OptionalCallOptions<T> {
  /** The `IamUserConfig` field this call populates, e.g. `"accessKeys"`. */
  field: string;
  operation: string;
  userName: string | null;
  errors: CollectionError[];
  /** Sink for the names of fields that could not be read. */
  unobserved: string[];
  call: () => Promise<T>;
}

/**
 * Runs one IAM call, treating "does not exist" as a `null` answer and anything
 * else as an unobserved field.
 *
 * Mirrors `readSetting` in the S3 collector; kept separate because the
 * tolerated codes and the `resourceType` on the error differ, and sharing them
 * would take more configuration than it saves.
 *
 * The distinction it preserves matters most for `GetLoginProfile`. A
 * `NoSuchEntity` there is the ordinary way AWS says "this user has no console
 * password", and it correctly yields `hasConsoleAccess: false`. But any *other*
 * failure would also have produced `false` under the previous version of this
 * code — silently claiming a user cannot sign in when we simply failed to ask.
 * That turned a swallowed error into a missed missing-MFA finding, which is the
 * worst kind of bug for a security tool: a false negative you cannot see.
 *
 * @returns The call's value, `null` if the entity does not exist, and also
 *          `null` if the call failed — with the field named in `unobserved` in
 *          that second case, so a rule can tell the two apart.
 */
async function optional<T>(options: OptionalCallOptions<T>): Promise<T | null> {
  try {
    return await options.call();
  } catch (error) {
    const code = awsErrorCode(error);
    if (NOT_FOUND_CODES.includes(code)) return null;

    options.unobserved.push(options.field);
    options.errors.push({
      resourceType: "iam_user",
      resourceName: options.userName,
      operation: options.operation,
      message: `${code || "Error"}: ${errorMessage(error)}`,
    });
    return null;
  }
}

// ---------------------------------------------------------------------------
// Policy document parsing
// ---------------------------------------------------------------------------

/**
 * Parses an IAM policy document.
 *
 * Two differences from the S3 bucket-policy case, both easy to miss:
 *
 * 1. **IAM returns policy documents URL-encoded.** `GetUserPolicy` and
 *    `GetPolicyVersion` hand back something like `%7B%22Version%22%3A...`
 *    rather than raw JSON. Feeding that straight to `JSON.parse` throws a
 *    confusing "Unexpected token %" error. `GetBucketPolicy`, inconsistently,
 *    does *not* encode. Rather than hard-coding which API does what, the logic
 *    below tries a direct parse first and only falls back to decoding — that
 *    stays correct whichever behaviour the service (or LocalStack's emulation
 *    of it) actually exhibits.
 *
 * 2. **`Statement` may be a single object rather than an array**, exactly as in
 *    bucket policies, and it is normalized to an array here so no rule has to
 *    handle both forms.
 *
 * @returns The parsed document, or `null` if it could not be parsed by either
 *          route. Null means "not evaluated" — a rule must not read it as safe.
 *
 * Exported for tests rather than as public API.
 */
export function parsePolicyDocument(raw: string): PolicyDocument | null {
  const attempts = [raw];
  try {
    attempts.push(decodeURIComponent(raw));
  } catch {
    // decodeURIComponent throws on malformed percent-escapes; if it does, the
    // direct parse attempt is still worth making.
  }

  for (const candidate of attempts) {
    try {
      const parsed = JSON.parse(candidate) as {
        Version?: string;
        Statement?: unknown;
      };
      if (parsed.Statement === undefined) continue;
      return {
        Version: parsed.Version,
        Statement: Array.isArray(parsed.Statement)
          ? parsed.Statement
          : [parsed.Statement],
      } as PolicyDocument;
    } catch {
      // Try the next candidate.
    }
  }
  return null;
}

/**
 * Computes an access key's age in whole days at collection time.
 *
 * Deliberately calculated during collection rather than when a finding is
 * displayed. If a stored scan recomputed age at read time, a "key older than 90
 * days" finding would appear on a scan taken when the key was 30 days old,
 * simply because the report was opened three months later. A scan should mean
 * what it meant when it ran.
 *
 * Exported for tests rather than as public API.
 */
export function ageInDays(createdAt: Date | undefined, now: Date): number | null {
  if (!createdAt) return null;
  const millis = now.getTime() - createdAt.getTime();
  return Math.floor(millis / 86_400_000);
}

// ---------------------------------------------------------------------------
// Managed policy resolution
// ---------------------------------------------------------------------------

/**
 * Fetches the document behind a managed policy ARN.
 *
 * `ListAttachedUserPolicies` returns only names and ARNs — the actual
 * permissions require two further calls: `GetPolicy` to find which version is
 * the default (a managed policy can have up to five versions, and only one is
 * live), then `GetPolicyVersion` to retrieve that version's document. Reading
 * any version other than the default would report permissions that are not
 * actually in effect.
 *
 * @param cache Memo across all users in one scan. Managed policies are shared —
 *              `AdministratorAccess` may be attached to a dozen users — and
 *              without this the same two calls would repeat for each of them.
 * @returns The document, or `null` when it could not be retrieved (which for
 *          AWS-managed policies can happen on a restricted read-only role).
 */
async function resolveManagedPolicy(
  iam: IAMClient,
  policyArn: string,
  userName: string,
  errors: CollectionError[],
  unobserved: string[],
  cache: Map<string, PolicyDocument | null>,
): Promise<PolicyDocument | null> {
  const cached = cache.get(policyArn);
  if (cached !== undefined) return cached;

  const policy = await optional({
    field: "attachedPolicies",
    operation: "GetPolicy",
    userName,
    errors,
    unobserved,
    call: () => iam.send(new GetPolicyCommand({ PolicyArn: policyArn })),
  });
  const versionId = policy?.Policy?.DefaultVersionId;
  if (!versionId) {
    cache.set(policyArn, null);
    return null;
  }

  const version = await optional({
    field: "attachedPolicies",
    operation: "GetPolicyVersion",
    userName,
    errors,
    unobserved,
    call: () =>
      iam.send(
        new GetPolicyVersionCommand({ PolicyArn: policyArn, VersionId: versionId }),
      ),
  });
  const raw = version?.PolicyVersion?.Document;
  const document = raw ? parsePolicyDocument(raw) : null;

  cache.set(policyArn, document);
  return document;
}

/**
 * Resolves one IAM group down to the policies it grants its members.
 *
 * `ListGroupsForUser` returns only group names, which says nothing about what
 * membership actually confers. Without this step a user whose every permission
 * arrives through a group looks like an account with no permissions at all —
 * the false negative described on {@link GroupMembership}.
 *
 * @param groupCache Memo across the whole scan, keyed by group name. Groups
 *                   exist precisely to be shared, so a `developers` group with
 *                   ten members would otherwise be resolved ten times. One
 *                   consequence worth knowing: if resolving a group fails, the
 *                   error is attributed to whichever user happened to trigger
 *                   the lookup first, and later members reuse the cached result
 *                   without recording an error of their own. The `unobserved`
 *                   marker on that first user is the durable signal.
 */
async function resolveGroup(
  iam: IAMClient,
  groupName: string,
  userName: string,
  errors: CollectionError[],
  unobserved: string[],
  policyCache: Map<string, PolicyDocument | null>,
  groupCache: Map<string, GroupMembership>,
): Promise<GroupMembership> {
  const cached = groupCache.get(groupName);
  if (cached) return cached;

  const [attachedResponse, inlineResponse] = await Promise.all([
    optional({
      field: "groups",
      operation: "ListAttachedGroupPolicies",
      userName,
      errors,
      unobserved,
      call: () =>
        iam.send(new ListAttachedGroupPoliciesCommand({ GroupName: groupName })),
    }),
    optional({
      field: "groups",
      operation: "ListGroupPolicies",
      userName,
      errors,
      unobserved,
      call: () => iam.send(new ListGroupPoliciesCommand({ GroupName: groupName })),
    }),
  ]);

  // Managed policies attached to a group go through the same ARN cache as
  // user-level ones — the same policy is frequently attached in both places.
  const attachedPolicies: AttachedPolicySummary[] = await Promise.all(
    (attachedResponse?.AttachedPolicies ?? [])
      .filter(
        (policy): policy is { PolicyName: string; PolicyArn: string } =>
          typeof policy.PolicyName === "string" &&
          typeof policy.PolicyArn === "string",
      )
      .map(async (policy) => ({
        policyName: policy.PolicyName,
        policyArn: policy.PolicyArn,
        document: await resolveManagedPolicy(
          iam,
          policy.PolicyArn,
          userName,
          errors,
          unobserved,
          policyCache,
        ),
      })),
  );

  const inlinePolicies: InlinePolicySummary[] = await Promise.all(
    (inlineResponse?.PolicyNames ?? []).map(async (policyName) => {
      const response = await optional({
        field: "groups",
        operation: "GetGroupPolicy",
        userName,
        errors,
        unobserved,
        call: () =>
          iam.send(
            new GetGroupPolicyCommand({
              GroupName: groupName,
              PolicyName: policyName,
            }),
          ),
      });
      const raw = response?.PolicyDocument;
      return { policyName, document: raw ? parsePolicyDocument(raw) : null };
    }),
  );

  const membership: GroupMembership = {
    groupName,
    attachedPolicies,
    inlinePolicies,
  };
  groupCache.set(groupName, membership);
  return membership;
}

// ---------------------------------------------------------------------------
// Per-user collection
// ---------------------------------------------------------------------------

/**
 * Gathers everything observable about one IAM user.
 *
 * The six independent list calls run concurrently; the policy-document lookups
 * they feed into necessarily run afterwards, since they need the ARNs and names
 * those lists return.
 *
 * @param errors Shared sink. A user always yields a resource even if some of
 *               its sub-calls fail, so the inventory records that the user
 *               exists rather than dropping it.
 */
async function collectUser(
  iam: IAMClient,
  user: IdentifiedUser,
  collectedAt: string,
  now: Date,
  errors: CollectionError[],
  policyCache: Map<string, PolicyDocument | null>,
  groupCache: Map<string, GroupMembership>,
): Promise<IamUserResource> {
  const userName = user.UserName;

  // Names of the config fields this user's scan could not read.
  const unobserved: string[] = [];

  const [
    attachedResponse,
    inlineResponse,
    mfaResponse,
    keysResponse,
    groupsResponse,
    tagsResponse,
    loginProfile,
  ] = await Promise.all([
    optional({
      field: "attachedPolicies",
      operation: "ListAttachedUserPolicies",
      userName,
      errors,
      unobserved,
      call: () =>
        iam.send(new ListAttachedUserPoliciesCommand({ UserName: userName })),
    }),
    optional({
      field: "inlinePolicies",
      operation: "ListUserPolicies",
      userName,
      errors,
      unobserved,
      call: () => iam.send(new ListUserPoliciesCommand({ UserName: userName })),
    }),
    optional({
      field: "mfaDeviceIds",
      operation: "ListMFADevices",
      userName,
      errors,
      unobserved,
      call: () => iam.send(new ListMFADevicesCommand({ UserName: userName })),
    }),
    optional({
      field: "accessKeys",
      operation: "ListAccessKeys",
      userName,
      errors,
      unobserved,
      call: () => iam.send(new ListAccessKeysCommand({ UserName: userName })),
    }),
    optional({
      field: "groupNames",
      operation: "ListGroupsForUser",
      userName,
      errors,
      unobserved,
      call: () => iam.send(new ListGroupsForUserCommand({ UserName: userName })),
    }),
    // ListUsers does not include tags, unlike most AWS list APIs, so tags need
    // their own call.
    optional({
      field: "tags",
      operation: "ListUserTags",
      userName,
      errors,
      unobserved,
      call: () => iam.send(new ListUserTagsCommand({ UserName: userName })),
    }),
    // A `NoSuchEntity` here is the normal, expected result for any user without
    // console access, and `optional` turns it into null without marking the
    // field unobserved. That null is what makes the missing-MFA rule precise:
    // demanding MFA of a service account with no password to protect would be
    // a false positive. Any other failure *does* mark `hasConsoleAccess`
    // unobserved — see the note on `optional`.
    optional({
      field: "hasConsoleAccess",
      operation: "GetLoginProfile",
      userName,
      errors,
      unobserved,
      call: () => iam.send(new GetLoginProfileCommand({ UserName: userName })),
    }),
  ]);

  // --- Managed policies ----------------------------------------------------
  const attachedPolicies: AttachedPolicySummary[] = await Promise.all(
    (attachedResponse?.AttachedPolicies ?? [])
      .filter(
        (policy): policy is { PolicyName: string; PolicyArn: string } =>
          typeof policy.PolicyName === "string" &&
          typeof policy.PolicyArn === "string",
      )
      .map(async (policy) => ({
        policyName: policy.PolicyName,
        policyArn: policy.PolicyArn,
        document: await resolveManagedPolicy(
          iam,
          policy.PolicyArn,
          userName,
          errors,
          unobserved,
          policyCache,
        ),
      })),
  );

  // --- Inline policies -----------------------------------------------------
  // Inline policies are easy to overlook in a manual audit because they do not
  // appear in the account's policy list at all, which makes them a common
  // hiding place for over-broad grants. Each name needs its own GetUserPolicy.
  const inlinePolicies: InlinePolicySummary[] = await Promise.all(
    (inlineResponse?.PolicyNames ?? []).map(async (policyName) => {
      const response = await optional({
        field: "inlinePolicies",
        operation: "GetUserPolicy",
        userName,
        errors,
        unobserved,
        call: () =>
          iam.send(
            new GetUserPolicyCommand({ UserName: userName, PolicyName: policyName }),
          ),
      });
      const raw = response?.PolicyDocument;
      return {
        policyName,
        document: raw ? parsePolicyDocument(raw) : null,
      };
    }),
  );

  // --- Groups --------------------------------------------------------------
  // Resolved rather than just named, so that permissions inherited through a
  // group are visible to a rule. Membership lists are short in practice, so
  // these run concurrently and the cache absorbs the overlap between users.
  const groupNames = (groupsResponse?.Groups ?? [])
    .map((group) => group.GroupName)
    .filter((name): name is string => typeof name === "string");

  const groups = await Promise.all(
    groupNames.map((groupName) =>
      resolveGroup(
        iam,
        groupName,
        userName,
        errors,
        unobserved,
        policyCache,
        groupCache,
      ),
    ),
  );

  // --- Access keys ---------------------------------------------------------
  const accessKeys: AccessKeySummary[] = (keysResponse?.AccessKeyMetadata ?? [])
    .filter(
      (key): key is AccessKeyMetadata & { AccessKeyId: string } =>
        typeof key.AccessKeyId === "string",
    )
    .map((key) => ({
      accessKeyId: key.AccessKeyId,
      status: key.Status === "Inactive" ? "Inactive" : "Active",
      createdAt: key.CreateDate?.toISOString() ?? null,
      ageInDays: ageInDays(key.CreateDate, now),
    }));

  const tags: Record<string, string> = {};
  for (const tag of tagsResponse?.Tags ?? []) {
    if (tag.Key) tags[tag.Key] = tag.Value ?? "";
  }

  return {
    id: user.Arn,
    type: "iam_user",
    name: userName,
    region: IAM_REGION,
    tags,
    collectedAt,
    // De-duplicated: several calls map to the same config field, so a user
    // whose managed-policy lookup failed twice should name the field once.
    unobserved: [...new Set(unobserved)],
    config: {
      userName,
      arn: user.Arn,
      createdAt: user.CreateDate?.toISOString() ?? null,
      passwordLastUsed: user.PasswordLastUsed?.toISOString() ?? null,
      hasConsoleAccess: loginProfile !== null,
      mfaDeviceIds: (mfaResponse?.MFADevices ?? [])
        .map((device) => device.SerialNumber)
        .filter((serial): serial is string => typeof serial === "string"),
      accessKeys,
      attachedPolicies,
      inlinePolicies,
      groups,
    },
  };
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Collects every IAM user in the account.
 *
 * `ListUsers` paginates with a `Marker`/`IsTruncated` pair rather than the
 * `NextToken` style EC2 uses — IAM is one of the older AWS services and kept
 * its original convention. The loop below follows it to completion; stopping
 * after the first page would produce a scan that looks clean because it never
 * looked at the rest of the account.
 *
 * @param collectedAt ISO-8601 timestamp stamped on every resource in this run,
 *                    shared with the other collectors so one scan is a single
 *                    coherent snapshot.
 * @param client      Optional IAM client, for tests. Defaults to the
 *                    LocalStack-pinned client, which refuses any non-loopback
 *                    endpoint.
 * @returns Users collected and non-fatal errors. Does not throw.
 */
export async function collectIamUsers(
  collectedAt: string = new Date().toISOString(),
  client: IAMClient = createIAMClient(),
): Promise<IamCollectionResult> {
  const errors: CollectionError[] = [];
  const resources: IamUserResource[] = [];

  // Key ages are measured against a single instant so that every key in one
  // scan is dated consistently, rather than drifting as the scan progresses.
  const now = new Date(collectedAt);

  // Shared across all users: managed policies are commonly attached to several
  // users, and resolving each one once per scan avoids repeating two API calls
  // for every attachment.
  const policyCache = new Map<string, PolicyDocument | null>();

  // Groups exist to be shared, so resolving each one once per scan rather than
  // once per member is the difference between a handful of calls and dozens.
  const groupCache = new Map<string, GroupMembership>();

  let marker: string | undefined;
  do {
    let page;
    try {
      page = await client.send(new ListUsersCommand({ Marker: marker }));
    } catch (error) {
      errors.push({
        resourceType: "iam_user",
        resourceName: null,
        operation: "ListUsers",
        message: `${awsErrorCode(error) || "Error"}: ${errorMessage(error)}`,
      });
      break;
    }

    const users = (page.Users ?? []).filter(
      (user): user is IdentifiedUser =>
        typeof user.UserName === "string" && typeof user.Arn === "string",
    );

    // Users on a page are collected concurrently, up to the configured cap;
    // pages are walked in sequence because each marker is only known once the
    // previous page returns. A user costs seven or more API calls, so the cap
    // matters more here than anywhere else in the collector.
    const collected = await mapWithConcurrency(
      users,
      collectorConcurrency(),
      (user) =>
        collectUser(
          client,
          user,
          collectedAt,
          now,
          errors,
          policyCache,
          groupCache,
        ),
    );
    resources.push(...collected);

    marker = page.IsTruncated ? page.Marker : undefined;
  } while (marker);

  // Stable ordering so repeated scans of an unchanged account are diffable.
  resources.sort((a, b) => a.name.localeCompare(b.name));

  return { resources, errors };
}
