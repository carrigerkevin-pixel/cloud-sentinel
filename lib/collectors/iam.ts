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
 *   ListGroupsForUser          permissions inherited invisibly
 *   GetLoginProfile            whether the user can sign in to the console
 *   ListUserTags               tags (ListUsers does not return them)
 */

import {
  type AccessKeyMetadata,
  GetLoginProfileCommand,
  GetPolicyCommand,
  GetPolicyVersionCommand,
  GetUserPolicyCommand,
  type IAMClient,
  ListAccessKeysCommand,
  ListAttachedUserPoliciesCommand,
  ListGroupsForUserCommand,
  ListMFADevicesCommand,
  ListUserPoliciesCommand,
  ListUserTagsCommand,
  ListUsersCommand,
  type User,
} from "@aws-sdk/client-iam";

import { createIAMClient } from "../aws/localstack.ts";
import type {
  AccessKeySummary,
  AttachedPolicySummary,
  CollectionError,
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

/**
 * Runs one IAM call, treating "does not exist" as a `null` answer and anything
 * else as a recorded failure.
 *
 * Mirrors `absentAsNull` in the S3 collector; kept as a separate local function
 * because the tolerated codes and the `resourceType` on the error differ, and a
 * shared abstraction across both would need more configuration than it saves.
 *
 * @param errors Sink that unexpected failures are appended to. Mutated rather
 *               than returned so a long chain of calls does not have to thread
 *               a result type through every line.
 * @returns The call's value, `null` if the entity does not exist, and also
 *          `null` if the call failed. As in the S3 collector, the caller must
 *          consult `errors` to tell a real absence from a failed observation.
 */
async function optional<T>(
  operation: string,
  userName: string | null,
  errors: CollectionError[],
  call: () => Promise<T>,
): Promise<T | null> {
  try {
    return await call();
  } catch (error) {
    if (NOT_FOUND_CODES.includes(awsErrorCode(error))) return null;
    errors.push({
      resourceType: "iam_user",
      resourceName: userName,
      operation,
      message: `${awsErrorCode(error) || "Error"}: ${errorMessage(error)}`,
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
 */
function parsePolicyDocument(raw: string): PolicyDocument | null {
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
 */
function ageInDays(createdAt: Date | undefined, now: Date): number | null {
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
  cache: Map<string, PolicyDocument | null>,
): Promise<PolicyDocument | null> {
  const cached = cache.get(policyArn);
  if (cached !== undefined) return cached;

  const policy = await optional("GetPolicy", userName, errors, () =>
    iam.send(new GetPolicyCommand({ PolicyArn: policyArn })),
  );
  const versionId = policy?.Policy?.DefaultVersionId;
  if (!versionId) {
    cache.set(policyArn, null);
    return null;
  }

  const version = await optional("GetPolicyVersion", userName, errors, () =>
    iam.send(
      new GetPolicyVersionCommand({ PolicyArn: policyArn, VersionId: versionId }),
    ),
  );
  const raw = version?.PolicyVersion?.Document;
  const document = raw ? parsePolicyDocument(raw) : null;

  cache.set(policyArn, document);
  return document;
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
): Promise<IamUserResource> {
  const userName = user.UserName;

  const [
    attachedResponse,
    inlineResponse,
    mfaResponse,
    keysResponse,
    groupsResponse,
    tagsResponse,
    loginProfile,
  ] = await Promise.all([
    optional("ListAttachedUserPolicies", userName, errors, () =>
      iam.send(new ListAttachedUserPoliciesCommand({ UserName: userName })),
    ),
    optional("ListUserPolicies", userName, errors, () =>
      iam.send(new ListUserPoliciesCommand({ UserName: userName })),
    ),
    optional("ListMFADevices", userName, errors, () =>
      iam.send(new ListMFADevicesCommand({ UserName: userName })),
    ),
    optional("ListAccessKeys", userName, errors, () =>
      iam.send(new ListAccessKeysCommand({ UserName: userName })),
    ),
    optional("ListGroupsForUser", userName, errors, () =>
      iam.send(new ListGroupsForUserCommand({ UserName: userName })),
    ),
    // ListUsers does not include tags, unlike most AWS list APIs, so tags need
    // their own call.
    optional("ListUserTags", userName, errors, () =>
      iam.send(new ListUserTagsCommand({ UserName: userName })),
    ),
    // A `NoSuchEntity` here is the normal, expected result for any user without
    // console access, and `optional` turns it into null. That null is what
    // makes the missing-MFA rule precise: demanding MFA of a service account
    // that has no password to protect would be a false positive.
    optional("GetLoginProfile", userName, errors, () =>
      iam.send(new GetLoginProfileCommand({ UserName: userName })),
    ),
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
      const response = await optional("GetUserPolicy", userName, errors, () =>
        iam.send(
          new GetUserPolicyCommand({ UserName: userName, PolicyName: policyName }),
        ),
      );
      const raw = response?.PolicyDocument;
      return {
        policyName,
        document: raw ? parsePolicyDocument(raw) : null,
      };
    }),
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
      groupNames: (groupsResponse?.Groups ?? [])
        .map((group) => group.GroupName)
        .filter((name): name is string => typeof name === "string"),
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

    // Users on a page are collected concurrently; pages are walked in sequence
    // because each marker is only known once the previous page returns.
    const collected = await Promise.all(
      users.map((user) =>
        collectUser(client, user, collectedAt, now, errors, policyCache),
      ),
    );
    resources.push(...collected);

    marker = page.IsTruncated ? page.Marker : undefined;
  } while (marker);

  // Stable ordering so repeated scans of an unchanged account are diffable.
  resources.sort((a, b) => a.name.localeCompare(b.name));

  return { resources, errors };
}
