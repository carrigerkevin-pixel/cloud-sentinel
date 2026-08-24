/**
 * CloudSentinel — normalized resource model.
 *
 * This file defines the single data shape that every part of CloudSentinel
 * agrees on. It contains types only: no imports, no logic, nothing that runs at
 * runtime. TypeScript erases all of it during compilation.
 *
 * Where it sits in the architecture:
 *
 *   LocalStack --> collectors (lib/collectors/*) --> Resource[] --> rule engine
 *                                                         |
 *                                                         +-----> Postgres
 *                                                         +-----> dashboard
 *
 * Why a normalized model exists at all: the three AWS APIs CloudSentinel reads
 * return completely unrelated shapes. `ListBuckets` returns `{ Name,
 * CreationDate }`; `DescribeSecurityGroups` returns `{ GroupId, IpPermissions
 * }`; `ListUsers` returns `{ UserName, Arn, PasswordLastUsed }`. Worse, the
 * interesting security details are not in those responses at all — they live
 * behind a dozen follow-up calls (GetBucketPolicy, GetPublicAccessBlock,
 * ListMFADevices, ...). If the rule engine consumed raw SDK output, every rule
 * would need to know AWS SDK internals and every rule would need its own
 * error handling for missing sub-resources. Instead the collectors do that
 * gathering once and emit the flat, uniform structures below.
 *
 * The design contract, which the collectors are responsible for upholding:
 *
 *   - A `Resource` describes the *observed* state of one cloud resource. It
 *     records facts, never judgements. There is no `isPublic` or `isCompliant`
 *     field anywhere in this file — deciding what is a problem is the rule
 *     engine's job, and keeping the two separate means rules can be added or
 *     retuned without re-collecting anything.
 *   - Absent data is modelled explicitly as `null`, and `null` means "AWS says
 *     this is not configured", which is frequently the finding itself. A bucket
 *     with no Block Public Access configuration returns a 404 from
 *     `GetPublicAccessBlock`, and that missing configuration is precisely what
 *     CIS wants flagged. Collapsing that into a default object would erase the
 *     signal.
 *   - Every field below exists to support at least one of the twelve findings
 *     promised by `EXPECTED_FINDINGS` in scripts/seed-localstack.ts. Each
 *     config block lists which ones.
 */

// ---------------------------------------------------------------------------
// IAM policy documents
// ---------------------------------------------------------------------------

/**
 * A single statement inside an IAM or S3 bucket policy.
 *
 * AWS's JSON policy grammar is deliberately loose: `Action`, `Resource`, and
 * `Principal` each accept either a single string or an array of strings, and
 * `Principal` additionally accepts the object form
 * (`{ "AWS": "arn:..." }`) or the literal string `"*"` for anonymous access.
 * These union types mirror that looseness rather than hiding it, because a
 * rule that checks for public access has to handle every one of those spellings
 * — `"*"`, `["*"]`, and `{ "AWS": "*" }` all mean "anyone on the internet".
 *
 * Normalizing the shapes here would be tempting but wrong: CloudSentinel
 * reports on what AWS actually returned, and a rule that silently rewrote the
 * policy before evaluating it would be hard to trust or debug.
 */
export interface PolicyStatement {
  /** Optional statement identifier. Useful for citing the exact statement in a finding. */
  Sid?: string;
  Effect: "Allow" | "Deny";
  /** Missing on resource-based policies that use `NotAction` instead. */
  Action?: string | string[];
  NotAction?: string | string[];
  Resource?: string | string[];
  NotResource?: string | string[];
  /**
   * Present on resource-based policies (bucket policies, trust policies) and
   * absent on identity-based ones, where the principal is implied by whoever
   * the policy is attached to.
   */
  Principal?: PolicyPrincipal;
  NotPrincipal?: PolicyPrincipal;
  /**
   * Condition keys that narrow the statement (source IP, MFA presence, and so
   * on). A wildcard statement guarded by a tight condition may be acceptable,
   * so rules must inspect this before flagging — an unconditional wildcard and
   * a conditioned one are very different risks.
   */
  Condition?: Record<string, Record<string, string | string[]>>;
}

/**
 * The `Principal` element. `"*"` means anonymous/public; the object form maps
 * a principal category (`AWS`, `Service`, `Federated`, `CanonicalUser`) to one
 * or more identifiers.
 */
export type PolicyPrincipal = "*" | Record<string, string | string[]>;

/** A parsed IAM/S3 policy document. */
export interface PolicyDocument {
  /** Policy language version, effectively always "2012-10-17" in practice. */
  Version?: string;
  Statement: PolicyStatement[];
}

// ---------------------------------------------------------------------------
// Common envelope
// ---------------------------------------------------------------------------

/**
 * The kinds of resource CloudSentinel currently understands.
 *
 * This is a string union rather than a TypeScript `enum` deliberately: the
 * values are written straight to Postgres and to JSON, and a plain string union
 * keeps the wire format and the type identical with no conversion layer. It is
 * also the discriminant of the {@link Resource} union — see below.
 */
export type ResourceType = "s3_bucket" | "security_group" | "iam_user";

/**
 * Fields shared by every resource regardless of service.
 *
 * These are exactly the columns the future `resources` table needs, which is
 * why they are separated from the per-service `config`: one table can store a
 * mixed inventory, with the service-specific detail kept in a JSONB column.
 * It is also what lets the dashboard render S3 buckets, security groups, and
 * IAM users in a single sortable list.
 *
 * Not exported on its own — consumers use the {@link Resource} union so that
 * `type` and `config` are always correlated.
 */
interface ResourceBase {
  /**
   * Globally unique, stable identifier — an ARN where AWS provides one,
   * otherwise the service's natural id (a security group's `sg-...`).
   *
   * Stability matters: this is the key that ties a finding to a resource across
   * repeated scans, so a bucket flagged on Monday and fixed on Tuesday resolves
   * the same finding rather than creating a second one.
   */
  id: string;

  /** Discriminant. Determines which `config` shape this resource carries. */
  type: ResourceType;

  /** Short human-readable label for the dashboard: bucket name, group name, user name. */
  name: string;

  /**
   * AWS region. IAM is a global service, so IAM users are recorded as
   * `"global"` rather than being forced into a region they do not belong to.
   */
  region: string;

  /**
   * Resource tags, flattened from AWS's `[{ Key, Value }]` array into a plain
   * object because every consumer wants lookup by key, not iteration. Empty
   * object when the resource is untagged — untagged resources are ordinary, so
   * this is not modelled as `null`.
   */
  tags: Record<string, string>;

  /**
   * When this snapshot was taken, as an ISO-8601 string.
   *
   * ISO strings rather than `Date` objects: this structure gets serialized to
   * JSON and stored in Postgres, and `JSON.parse` turns a `Date` back into a
   * string anyway. Committing to the string form everywhere avoids a type that
   * quietly changes across a serialization boundary.
   *
   * Findings are only meaningful with a timestamp — "this bucket was public"
   * needs a "when" to be actionable.
   */
  collectedAt: string;
}

// ---------------------------------------------------------------------------
// S3
// ---------------------------------------------------------------------------

/**
 * S3 Block Public Access settings, the account/bucket-level override that beats
 * both ACLs and bucket policies.
 *
 * All four flags on is the secure baseline. The seed script turns all four off
 * on the vulnerable bucket, because S3 will otherwise reject a public bucket
 * policy outright.
 *
 * Supports: "S3 bucket has Block Public Access fully disabled".
 */
export interface PublicAccessBlockConfig {
  blockPublicAcls: boolean;
  ignorePublicAcls: boolean;
  blockPublicPolicy: boolean;
  restrictPublicBuckets: boolean;
}

/**
 * One grant from a bucket ACL.
 *
 * The legacy access-control mechanism that predates bucket policies. It still
 * matters because a single grant to the `AllUsers` group makes a bucket
 * world-readable regardless of how careful the bucket policy is — a classic
 * way buckets leak.
 *
 * Supports: "S3 bucket ACL grants READ to AllUsers".
 */
export interface BucketAclGrant {
  /**
   * `Group` grants are the dangerous ones. AWS identifies the two public groups
   * by URI: `http://acs.amazonaws.com/groups/global/AllUsers` is literally
   * everyone, and `.../AuthenticatedUsers` is every AWS account holder in the
   * world — barely better.
   */
  granteeType: "CanonicalUser" | "Group" | "AmazonCustomerByEmail" | "Unknown";
  /** Group URI for `Group` grants; canonical user id or email otherwise. */
  granteeId: string | null;
  /** Display name when AWS supplies one. */
  granteeName: string | null;
  permission: "FULL_CONTROL" | "READ" | "WRITE" | "READ_ACP" | "WRITE_ACP";
}

/**
 * Everything CloudSentinel observes about one S3 bucket.
 *
 * Assembled from ListBuckets plus GetPublicAccessBlock, GetBucketPolicy,
 * GetBucketAcl, GetBucketVersioning, GetBucketLogging, and GetBucketEncryption.
 * Each of those can fail independently — a bucket legitimately may have no
 * policy — so the nullable fields below are the normal case, not error states.
 */
export interface S3BucketConfig {
  /** Bucket creation time (ISO-8601), or null if AWS omitted it. */
  createdAt: string | null;

  /**
   * Block Public Access configuration, or null when the bucket has none set.
   *
   * Null is *less* safe than an all-false object would suggest: it means
   * nothing is blocking public ACLs or policies at the bucket level. Rules must
   * treat null as "no protection", not as "unknown, skip".
   */
  publicAccessBlock: PublicAccessBlockConfig | null;

  /**
   * Parsed bucket policy, or null when the bucket has no policy attached
   * (AWS returns `NoSuchBucketPolicy`, which is a completely normal state).
   *
   * Supports: "S3 bucket policy grants s3:GetObject to Principal '*'".
   */
  policy: PolicyDocument | null;

  /**
   * Raw policy JSON exactly as AWS returned it, kept alongside the parsed form.
   *
   * Two reasons: a finding should be able to quote the offending policy
   * verbatim in the dashboard, and if a policy ever fails to parse the raw text
   * is the only way to diagnose why.
   */
  policyRaw: string | null;

  /** ACL grants. Empty array when the ACL grants nothing beyond the owner. */
  aclGrants: BucketAclGrant[];

  /**
   * Versioning state. AWS omits the field entirely on a bucket where
   * versioning was never enabled, which the collector normalizes to
   * `"Disabled"` — the three states are genuinely distinct, since `Suspended`
   * means versioning existed once and old versions may still be present.
   *
   * Supports: "S3 bucket has versioning disabled".
   */
  versioning: "Enabled" | "Suspended" | "Disabled";

  /**
   * Whether server access logging is on. Without it there is no record of who
   * read from the bucket, so a leak cannot be investigated after the fact.
   *
   * Supports: "S3 bucket has no server access logging".
   */
  loggingEnabled: boolean;

  /** Destination bucket for access logs, when logging is enabled. */
  loggingTargetBucket: string | null;

  /**
   * Default server-side encryption algorithm (`AES256`, `aws:kms`), or null
   * when the bucket has no default encryption rule. Not in the seeded findings
   * list, but collected now because it is a standard CIS check and adding a
   * field later would mean re-running every scan.
   */
  encryptionAlgorithm: string | null;
}

/** An S3 bucket. */
export interface S3BucketResource extends ResourceBase {
  type: "s3_bucket";
  config: S3BucketConfig;
}

// ---------------------------------------------------------------------------
// EC2 security groups
// ---------------------------------------------------------------------------

/**
 * One normalized ingress or egress rule.
 *
 * EC2 returns these as `IpPermissions`, where a single entry can carry several
 * IPv4 ranges, IPv6 ranges, referenced security groups, and prefix lists at
 * once. That nesting is preserved rather than exploded into one rule per CIDR,
 * because a finding reads better as "tcp/22 open to 0.0.0.0/0 and ::/0" than as
 * two separate findings for the same hole.
 *
 * Supports the three security-group findings: tcp/22 from 0.0.0.0/0, tcp/3389
 * from 0.0.0.0/0, and tcp/22 from ::/0.
 */
export interface SecurityGroupRule {
  /**
   * `tcp`, `udp`, `icmp`, or `-1`.
   *
   * `-1` is AWS's encoding for "all protocols" and is the most severe form this
   * field takes — a rule engine that only string-matches `"tcp"` would miss a
   * group that is wide open on everything.
   */
  protocol: string;

  /**
   * Port range. Null on protocols that have no ports (and when protocol is
   * `-1`, where AWS omits them to mean all ports). Null must therefore be read
   * as "every port", not as "no ports".
   */
  fromPort: number | null;
  toPort: number | null;

  /** IPv4 CIDRs allowed by this rule. `0.0.0.0/0` is the entire internet. */
  ipv4Ranges: string[];

  /** IPv6 CIDRs allowed by this rule. `::/0` is the IPv6 equivalent of 0.0.0.0/0. */
  ipv6Ranges: string[];

  /**
   * Other security groups allowed by this rule. Group-to-group references are
   * generally the *good* pattern — traffic is scoped to peer instances rather
   * than to an IP range — so rules should not flag these the way they flag CIDRs.
   */
  sourceSecurityGroupIds: string[];

  /** Descriptions AWS attaches to individual CIDR entries, useful context in a finding. */
  descriptions: string[];
}

/** Everything CloudSentinel observes about one security group. */
export interface SecurityGroupConfig {
  /** The `sg-...` identifier. Also used as the resource `id`, since LocalStack does not always return an ARN. */
  groupId: string;
  /** AWS requires a description on every security group, so this is effectively always present. */
  description: string;
  /** Owning VPC, or null for the legacy EC2-Classic shape. */
  vpcId: string | null;
  /** Inbound rules — where the internet-exposure findings come from. */
  ingressRules: SecurityGroupRule[];
  /**
   * Outbound rules. Collected because unrestricted egress is a data
   * exfiltration path and a standard benchmark check, even though the seeded
   * fixtures do not currently exercise it.
   */
  egressRules: SecurityGroupRule[];
}

/** An EC2 security group. */
export interface SecurityGroupResource extends ResourceBase {
  type: "security_group";
  config: SecurityGroupConfig;
}

// ---------------------------------------------------------------------------
// IAM
// ---------------------------------------------------------------------------

/**
 * An IAM access key belonging to a user.
 *
 * The secret is never retrievable after creation and is never collected —
 * CloudSentinel only needs the key's metadata to reason about it. Even for
 * throwaway LocalStack fixtures, keeping secrets out of the data model means
 * they can never end up in the database, in a log line, or on the dashboard.
 *
 * Supports: "IAM user has a long-lived access key".
 */
export interface AccessKeySummary {
  accessKeyId: string;
  status: "Active" | "Inactive";
  /** Creation time (ISO-8601), or null if AWS omitted it. */
  createdAt: string | null;
  /**
   * Age in whole days, computed at collection time.
   *
   * Precomputed rather than derived in the rule engine so that a rule like
   * "keys older than 90 days" is evaluated against the age at *scan* time. If
   * the age were computed when the finding is later displayed, a stored scan
   * would silently change its own verdict as time passed.
   */
  ageInDays: number | null;
}

/** A customer-managed or AWS-managed policy attached to a user. */
export interface AttachedPolicySummary {
  policyName: string;
  policyArn: string;
  /**
   * The policy's default-version document, or null when it could not be
   * fetched (AWS-managed policies need an extra GetPolicyVersion call, which
   * may be denied).
   *
   * Null means "not evaluated", so a rule must not treat a null document as
   * safe — the honest response is to report the check as inconclusive.
   *
   * Supports: "IAM user has an attached policy with Action '*' on Resource '*'".
   */
  document: PolicyDocument | null;
}

/**
 * A policy defined directly on the user rather than as a standalone object.
 *
 * Inline policies are easy to overlook in a real audit precisely because they
 * do not show up in the account's policy list, which makes them a favourite
 * hiding place for over-broad grants.
 *
 * Supports: "IAM user has an inline policy allowing unrestricted iam:PassRole".
 */
export interface InlinePolicySummary {
  policyName: string;
  document: PolicyDocument | null;
}

/** Everything CloudSentinel observes about one IAM user. */
export interface IamUserConfig {
  userName: string;
  /** Full ARN. Duplicated into the envelope's `id`, kept here so the config is self-contained. */
  arn: string;
  createdAt: string | null;
  /** Last console sign-in (ISO-8601), or null if the user has never signed in. Feeds dormant-account checks. */
  passwordLastUsed: string | null;

  /**
   * Whether the user has a login profile, i.e. can sign in to the AWS console
   * with a password.
   *
   * This is what makes the missing-MFA finding meaningful: a service account
   * with no console access has no password to protect, so demanding MFA of it
   * would be a false positive. The rule is the conjunction of this being true
   * and `mfaDeviceIds` being empty.
   *
   * Supports: "IAM user has console access but no MFA device".
   */
  hasConsoleAccess: boolean;

  /** Serial numbers/ARNs of enrolled MFA devices. Empty means no MFA. */
  mfaDeviceIds: string[];

  accessKeys: AccessKeySummary[];
  attachedPolicies: AttachedPolicySummary[];
  inlinePolicies: InlinePolicySummary[];

  /**
   * IAM groups the user belongs to.
   *
   * Collected because permissions inherited through a group are invisible when
   * looking at the user alone — a user with no attached policies can still be
   * an administrator via group membership. Group policy documents are not
   * resolved yet; that is a later enhancement.
   */
  groupNames: string[];
}

/** An IAM user. */
export interface IamUserResource extends ResourceBase {
  type: "iam_user";
  config: IamUserConfig;
}

// ---------------------------------------------------------------------------
// The union
// ---------------------------------------------------------------------------

/**
 * Any resource CloudSentinel has collected.
 *
 * This is a *discriminated union*: three object types that share a literal
 * `type` field with a different value in each. TypeScript uses that field to
 * narrow the union automatically, so a rule written like
 *
 *     if (resource.type === "s3_bucket") {
 *       resource.config.versioning;   // known to be S3BucketConfig here
 *     }
 *
 * gets full autocomplete inside the branch, and misreading a field that belongs
 * to a different service becomes a compile error rather than a runtime
 * `undefined`. A `switch` over `resource.type` that handles all three cases can
 * also be proven exhaustive by the compiler, so adding a fourth resource type
 * later surfaces every place that needs updating instead of failing silently in
 * production.
 *
 * That guarantee is the reason `config` is not typed as `unknown` or `any`.
 */
export type Resource = S3BucketResource | SecurityGroupResource | IamUserResource;

/**
 * Maps each `ResourceType` to its matching config type, so helpers can be
 * written generically — e.g. `ConfigFor<"s3_bucket">` is `S3BucketConfig`.
 */
export type ConfigFor<T extends ResourceType> = Extract<
  Resource,
  { type: T }
>["config"];

// ---------------------------------------------------------------------------
// Collection results
// ---------------------------------------------------------------------------

/**
 * A problem hit while collecting, recorded rather than thrown.
 *
 * Partial failure is the expected case in a real audit: one bucket in another
 * region denies access, one API is throttled. Aborting the whole scan because
 * of a single resource would make the tool useless against a real account, but
 * silently dropping the resource would be worse — the dashboard would show a
 * clean scan that simply never looked. So errors travel alongside the results
 * and get surfaced.
 */
export interface CollectionError {
  /** Which collector failed, so the message can say "S3" rather than just failing. */
  resourceType: ResourceType;
  /** The specific resource involved, or null when the failure was the top-level list call. */
  resourceName: string | null;
  /** Which AWS operation failed, e.g. "GetBucketPolicy". */
  operation: string;
  message: string;
}

/**
 * The complete output of one collection run — what `scripts/collect.ts` prints
 * and what the rule engine will eventually take as input.
 */
export interface ResourceInventory {
  /** When the run started (ISO-8601). Every resource in it shares this timestamp. */
  collectedAt: string;
  /** The endpoint that was scanned. Recorded so a saved inventory can never be mistaken for one taken from a different environment. */
  endpoint: string;
  region: string;
  resources: Resource[];
  /** Non-fatal failures. Empty array on a fully successful run. */
  errors: CollectionError[];
}
