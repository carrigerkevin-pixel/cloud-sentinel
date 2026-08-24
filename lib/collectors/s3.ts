/**
 * CloudSentinel — S3 collector.
 *
 * Reads every S3 bucket in the target environment and converts it into the
 * normalized {@link S3BucketResource} shape defined in lib/types/resource.ts.
 *
 * Where it sits in the architecture: this is stage one of the pipeline. It
 * talks to LocalStack, and nothing downstream of it ever touches the AWS SDK.
 *
 *   LocalStack --> [ collectS3Buckets ] --> S3BucketResource[] --> rule engine
 *
 * SECURITY: this module is strictly read-only. It issues only `List*` and
 * `Get*` commands — there is no `Put*`, `Delete*`, or `Create*` anywhere in the
 * file, and there must never be. scripts/seed-localstack.ts is the only part of
 * CloudSentinel permitted to change cloud state. A scanner that can modify what
 * it audits is a scanner nobody should point at production.
 *
 * The shape of the work, and the one genuinely tricky part:
 *
 * `ListBuckets` returns almost nothing of security interest — just names and
 * creation dates. Every setting that matters lives behind a separate API call,
 * and most of those calls *throw* when the feature is not configured. A bucket
 * with no policy raises `NoSuchBucketPolicy`; a bucket with no default
 * encryption raises `ServerSideEncryptionConfigurationNotFoundError`. Those are
 * not failures — they are the answer, and usually the answer that becomes a
 * finding. So every detail call goes through {@link absentAsNull}, which turns
 * a specific "not configured" error code into `null` while letting anything
 * else (network failure, denied permission, a LocalStack bug) be recorded as a
 * {@link CollectionError}.
 *
 * Getting that distinction wrong breaks the tool in one of two ways: treat
 * everything as fatal and a normal bucket crashes the scan; treat everything as
 * absent and a permissions error is silently reported as a clean bucket.
 */

import {
  GetBucketAclCommand,
  GetBucketEncryptionCommand,
  GetBucketLocationCommand,
  GetBucketLoggingCommand,
  GetBucketPolicyCommand,
  GetBucketTaggingCommand,
  GetBucketVersioningCommand,
  GetPublicAccessBlockCommand,
  ListBucketsCommand,
  type S3Client,
} from "@aws-sdk/client-s3";

import { AWS_REGION, createS3Client } from "../aws/localstack.ts";
import type {
  BucketAclGrant,
  CollectionError,
  PolicyDocument,
  PublicAccessBlockConfig,
  S3BucketConfig,
  S3BucketResource,
} from "../types/resource.ts";

// ---------------------------------------------------------------------------
// Error handling helpers
// ---------------------------------------------------------------------------

/**
 * What one collector returns: the resources it managed to read, plus any
 * non-fatal problems it hit along the way.
 *
 * Errors are returned rather than thrown so that one unreadable bucket does not
 * abort the scan of every other bucket, while still being impossible to ignore
 * — the caller has to do something with the array.
 */
export interface S3CollectionResult {
  resources: S3BucketResource[];
  errors: CollectionError[];
}

/**
 * AWS error codes that mean "this feature is simply not configured on this
 * bucket", per API.
 *
 * These are grouped by call rather than lumped into one list so that an
 * unexpected code from one API cannot be swallowed by another API's allowance.
 * `NotImplemented` and `MethodNotAllowed` appear in several entries because
 * LocalStack's free tier does not emulate every S3 sub-API; when that happens
 * the honest result is `null` ("we could not observe this") rather than a
 * fabricated default.
 */
const ABSENT_CODES = {
  publicAccessBlock: [
    "NoSuchPublicAccessBlockConfiguration",
    "NotImplemented",
  ],
  policy: ["NoSuchBucketPolicy", "NotImplemented"],
  acl: ["AccessControlListNotSupported", "NotImplemented", "MethodNotAllowed"],
  encryption: [
    "ServerSideEncryptionConfigurationNotFoundError",
    "NotImplemented",
  ],
  tagging: ["NoSuchTagSet", "NoSuchTagSetError", "NotImplemented"],
  location: ["NotImplemented"],
} as const;

/**
 * Reads the error code the AWS SDK v3 attaches to a failure.
 *
 * The SDK puts the service-side code on `error.name`, but some errors surface
 * it only under `$metadata`-adjacent fields, so both are checked. Written
 * defensively because a thrown value in JavaScript is not guaranteed to be an
 * `Error` at all.
 */
function awsErrorCode(error: unknown): string {
  if (typeof error !== "object" || error === null) return "";
  const candidate = error as { name?: string; Code?: string; code?: string };
  return candidate.name ?? candidate.Code ?? candidate.code ?? "";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Runs one AWS call, distinguishing "not configured" from "went wrong".
 *
 * @param absentCodes  Error codes that mean the feature is absent; these
 *                     resolve to `null`.
 * @param operation    API name, recorded on the error so a report can say
 *                     which call failed rather than just "S3 failed".
 * @param bucket       Bucket the call was about, for the same reason.
 * @param errors       Sink that unexpected failures are appended to. Mutated
 *                     rather than returned so the caller can collect across
 *                     many calls without threading a result type through
 *                     every line.
 * @param call         The call itself.
 * @returns The call's value, or `null` if the feature is absent **or** if the
 *          call failed. Both collapse to `null`, so the caller must consult
 *          `errors` to tell a real absence from a failed observation — see the
 *          note on `AttachedPolicySummary.document` in lib/types/resource.ts
 *          for why that distinction matters to a rule.
 */
async function absentAsNull<T>(
  absentCodes: readonly string[],
  operation: string,
  bucket: string,
  errors: CollectionError[],
  call: () => Promise<T>,
): Promise<T | null> {
  try {
    return await call();
  } catch (error) {
    if (absentCodes.includes(awsErrorCode(error))) return null;
    errors.push({
      resourceType: "s3_bucket",
      resourceName: bucket,
      operation,
      message: `${awsErrorCode(error) || "Error"}: ${errorMessage(error)}`,
    });
    return null;
  }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/**
 * Parses a bucket policy's JSON text into a {@link PolicyDocument}.
 *
 * Two AWS quirks are handled here:
 *
 * 1. `Statement` may be a single object instead of an array. The IAM policy
 *    grammar allows both, and a rule engine that assumed an array would throw
 *    on the single-statement form — which is exactly the form a hand-written
 *    "make this bucket public" policy usually takes.
 * 2. The document is URL-encoded in some IAM APIs. It is *not* for
 *    `GetBucketPolicy`, so no decoding happens here; the IAM collector will
 *    handle that case separately.
 *
 * @returns The parsed document, or `null` if the text is not valid JSON. A
 *          parse failure is deliberately not fatal — `policyRaw` still carries
 *          the original text so the problem can be diagnosed from the report.
 */
function parsePolicyDocument(raw: string): PolicyDocument | null {
  try {
    const parsed = JSON.parse(raw) as {
      Version?: string;
      Statement?: unknown;
    };
    const statement = parsed.Statement;
    if (statement === undefined) return null;
    return {
      Version: parsed.Version,
      Statement: Array.isArray(statement) ? statement : [statement],
    } as PolicyDocument;
  } catch {
    return null;
  }
}

/**
 * Normalizes S3's ACL grant list.
 *
 * `Grantee.Type` distinguishes the dangerous case: a `Group` grant whose URI is
 * `http://acs.amazonaws.com/groups/global/AllUsers` makes the bucket
 * world-accessible no matter how restrictive the bucket policy is. The URI is
 * preserved verbatim in `granteeId` so the rule engine can match on it — this
 * function classifies, it does not judge.
 */
function normalizeAclGrants(
  grants: Array<{
    Grantee?: {
      Type?: string;
      URI?: string;
      ID?: string;
      DisplayName?: string;
      EmailAddress?: string;
    };
    Permission?: string;
  }>,
): BucketAclGrant[] {
  return grants.map((grant) => {
    const grantee = grant.Grantee ?? {};
    const type: BucketAclGrant["granteeType"] =
      grantee.Type === "CanonicalUser" ||
      grantee.Type === "Group" ||
      grantee.Type === "AmazonCustomerByEmail"
        ? grantee.Type
        : "Unknown";

    return {
      granteeType: type,
      // For a Group grant the URI *is* the identity; for a user it is the
      // canonical id. Falling back through both keeps one field meaningful
      // across grantee types.
      granteeId: grantee.URI ?? grantee.ID ?? grantee.EmailAddress ?? null,
      granteeName: grantee.DisplayName ?? null,
      permission: (grant.Permission ?? "READ") as BucketAclGrant["permission"],
    };
  });
}

/** Flattens AWS's `[{ Key, Value }]` tag array into a plain lookup object. */
function normalizeTags(
  tagSet: Array<{ Key?: string; Value?: string }>,
): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const tag of tagSet) {
    if (tag.Key) tags[tag.Key] = tag.Value ?? "";
  }
  return tags;
}

// ---------------------------------------------------------------------------
// Per-bucket collection
// ---------------------------------------------------------------------------

/**
 * Gathers every observable setting for one bucket.
 *
 * The seven detail calls are independent of each other, so they run
 * concurrently with `Promise.all` rather than one after another. With a handful
 * of buckets the difference is small; against a real account with hundreds it
 * is the difference between a scan taking seconds and taking minutes. Error
 * attribution survives the concurrency because each call records its own
 * failure through {@link absentAsNull} before resolving to `null`.
 *
 * @param errors Shared sink; this function appends to it and never throws for
 *               a per-setting failure. A bucket always yields a resource, even
 *               a sparsely populated one, so the inventory reflects that the
 *               bucket exists.
 */
async function collectBucket(
  s3: S3Client,
  bucketName: string,
  createdAt: string | null,
  collectedAt: string,
  errors: CollectionError[],
): Promise<S3BucketResource> {
  const [
    publicAccessBlock,
    policyResponse,
    aclResponse,
    versioningResponse,
    loggingResponse,
    encryptionResponse,
    taggingResponse,
    locationResponse,
  ] = await Promise.all([
    absentAsNull(
      ABSENT_CODES.publicAccessBlock,
      "GetPublicAccessBlock",
      bucketName,
      errors,
      () => s3.send(new GetPublicAccessBlockCommand({ Bucket: bucketName })),
    ),
    absentAsNull(ABSENT_CODES.policy, "GetBucketPolicy", bucketName, errors, () =>
      s3.send(new GetBucketPolicyCommand({ Bucket: bucketName })),
    ),
    absentAsNull(ABSENT_CODES.acl, "GetBucketAcl", bucketName, errors, () =>
      s3.send(new GetBucketAclCommand({ Bucket: bucketName })),
    ),
    // Versioning has no "absent" error: AWS returns 200 with an empty body for
    // a bucket that never had versioning enabled, so the only codes tolerated
    // are none at all.
    absentAsNull([], "GetBucketVersioning", bucketName, errors, () =>
      s3.send(new GetBucketVersioningCommand({ Bucket: bucketName })),
    ),
    // Logging behaves the same way — 200 with no `LoggingEnabled` key.
    absentAsNull([], "GetBucketLogging", bucketName, errors, () =>
      s3.send(new GetBucketLoggingCommand({ Bucket: bucketName })),
    ),
    absentAsNull(
      ABSENT_CODES.encryption,
      "GetBucketEncryption",
      bucketName,
      errors,
      () => s3.send(new GetBucketEncryptionCommand({ Bucket: bucketName })),
    ),
    absentAsNull(ABSENT_CODES.tagging, "GetBucketTagging", bucketName, errors, () =>
      s3.send(new GetBucketTaggingCommand({ Bucket: bucketName })),
    ),
    absentAsNull(
      ABSENT_CODES.location,
      "GetBucketLocation",
      bucketName,
      errors,
      () => s3.send(new GetBucketLocationCommand({ Bucket: bucketName })),
    ),
  ]);

  // --- Block Public Access -------------------------------------------------
  // Null here means the bucket has no BPA configuration at all, which is the
  // *less* safe state — nothing is overriding a permissive ACL or policy.
  const pab: PublicAccessBlockConfig | null =
    publicAccessBlock?.PublicAccessBlockConfiguration
      ? {
          blockPublicAcls:
            publicAccessBlock.PublicAccessBlockConfiguration.BlockPublicAcls ??
            false,
          ignorePublicAcls:
            publicAccessBlock.PublicAccessBlockConfiguration.IgnorePublicAcls ??
            false,
          blockPublicPolicy:
            publicAccessBlock.PublicAccessBlockConfiguration
              .BlockPublicPolicy ?? false,
          restrictPublicBuckets:
            publicAccessBlock.PublicAccessBlockConfiguration
              .RestrictPublicBuckets ?? false,
        }
      : null;

  // --- Policy --------------------------------------------------------------
  const policyRaw = policyResponse?.Policy ?? null;

  // --- Versioning ----------------------------------------------------------
  // AWS omits `Status` entirely on a bucket where versioning was never turned
  // on. "Disabled" and "Suspended" are kept distinct because a suspended bucket
  // may still hold old object versions from when it was enabled.
  const versioning: S3BucketConfig["versioning"] =
    versioningResponse?.Status === "Enabled"
      ? "Enabled"
      : versioningResponse?.Status === "Suspended"
        ? "Suspended"
        : "Disabled";

  // --- Encryption ----------------------------------------------------------
  // Only the first rule is read: S3 permits exactly one default-encryption rule
  // per bucket, so a second entry would be a service-side anomaly, not config.
  const encryptionAlgorithm =
    encryptionResponse?.ServerSideEncryptionConfiguration?.Rules?.[0]
      ?.ApplyServerSideEncryptionByDefault?.SSEAlgorithm ?? null;

  // --- Region --------------------------------------------------------------
  // GetBucketLocation returns an empty/absent LocationConstraint for
  // us-east-1 — a historical quirk from before other regions existed.
  const region =
    locationResponse?.LocationConstraint === undefined ||
    locationResponse?.LocationConstraint === null ||
    (locationResponse.LocationConstraint as string) === ""
      ? AWS_REGION
      : (locationResponse.LocationConstraint as string);

  const config: S3BucketConfig = {
    createdAt,
    publicAccessBlock: pab,
    policy: policyRaw ? parsePolicyDocument(policyRaw) : null,
    policyRaw,
    aclGrants: normalizeAclGrants(aclResponse?.Grants ?? []),
    versioning,
    loggingEnabled: Boolean(loggingResponse?.LoggingEnabled),
    loggingTargetBucket: loggingResponse?.LoggingEnabled?.TargetBucket ?? null,
    encryptionAlgorithm,
  };

  return {
    // S3 bucket ARNs have no account id or region segment, so this form is the
    // real, canonical ARN rather than a placeholder.
    id: `arn:aws:s3:::${bucketName}`,
    type: "s3_bucket",
    name: bucketName,
    region,
    tags: normalizeTags(taggingResponse?.TagSet ?? []),
    collectedAt,
    config,
  };
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Collects every S3 bucket visible to the configured credentials.
 *
 * @param collectedAt ISO-8601 timestamp stamped on every resource in this run.
 *                    Passed in rather than generated here so that all three
 *                    collectors in a single scan share one timestamp, which is
 *                    what makes a scan a coherent point-in-time snapshot.
 * @param client      Optional S3 client, for tests. Defaults to the
 *                    LocalStack-pinned client, which refuses to talk to a
 *                    non-loopback endpoint.
 * @returns Buckets collected and non-fatal errors. If `ListBuckets` itself
 *          fails the resource list is empty and a single error describes why —
 *          this function does not throw.
 */
export async function collectS3Buckets(
  collectedAt: string = new Date().toISOString(),
  client: S3Client = createS3Client(),
): Promise<S3CollectionResult> {
  const errors: CollectionError[] = [];

  let listed;
  try {
    listed = await client.send(new ListBucketsCommand({}));
  } catch (error) {
    // A failure here is different in kind from a per-bucket failure: we learned
    // nothing at all, so it is recorded against the service rather than a named
    // resource (`resourceName: null`).
    errors.push({
      resourceType: "s3_bucket",
      resourceName: null,
      operation: "ListBuckets",
      message: `${awsErrorCode(error) || "Error"}: ${errorMessage(error)}`,
    });
    return { resources: [], errors };
  }

  const buckets = (listed.Buckets ?? []).filter(
    (bucket): bucket is { Name: string; CreationDate?: Date } =>
      typeof bucket.Name === "string",
  );

  const resources = await Promise.all(
    buckets.map((bucket) =>
      collectBucket(
        client,
        bucket.Name,
        bucket.CreationDate?.toISOString() ?? null,
        collectedAt,
        errors,
      ),
    ),
  );

  // Stable ordering so two scans of an unchanged environment produce identical
  // output — that makes diffing scans, and eyeballing them, actually useful.
  resources.sort((a, b) => a.name.localeCompare(b.name));

  return { resources, errors };
}
