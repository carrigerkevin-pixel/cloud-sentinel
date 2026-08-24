/**
 * CloudSentinel — Phase 1 fixture provisioner.
 *
 * Seeds a LocalStack environment with resources that a CSPM tool should flag,
 * plus a small compliant control group so the rule engine can be shown to
 * distinguish real findings from clean resources (a scanner tested only against
 * broken infrastructure cannot demonstrate a false-positive rate).
 *
 *   npm run seed              provision (idempotent, safe to re-run)
 *   npm run seed:down         tear everything back down
 *   npm run seed -- --list    print the fixture plan without touching LocalStack
 *
 * Safety: lib/aws/localstack.ts refuses any endpoint that is not loopback.
 */

import {
  CreateBucketCommand,
  DeleteBucketCommand,
  DeleteObjectsCommand,
  ListObjectVersionsCommand,
  PutBucketAclCommand,
  PutBucketLoggingCommand,
  PutBucketOwnershipControlsCommand,
  PutBucketPolicyCommand,
  PutBucketTaggingCommand,
  PutBucketVersioningCommand,
  PutObjectCommand,
  PutPublicAccessBlockCommand,
} from "@aws-sdk/client-s3";
import {
  AuthorizeSecurityGroupIngressCommand,
  CreateSecurityGroupCommand,
  DeleteSecurityGroupCommand,
  DescribeSecurityGroupsCommand,
  DescribeVpcsCommand,
  type EC2Client,
} from "@aws-sdk/client-ec2";
import {
  AddUserToGroupCommand,
  AttachGroupPolicyCommand,
  AttachUserPolicyCommand,
  CreateAccessKeyCommand,
  CreateGroupCommand,
  CreateLoginProfileCommand,
  CreatePolicyCommand,
  CreateUserCommand,
  DeleteAccessKeyCommand,
  DeleteGroupCommand,
  DeleteGroupPolicyCommand,
  DeleteLoginProfileCommand,
  DeletePolicyCommand,
  DeleteUserCommand,
  DeleteUserPolicyCommand,
  DetachGroupPolicyCommand,
  DetachUserPolicyCommand,
  type IAMClient,
  ListAccessKeysCommand,
  ListAttachedGroupPoliciesCommand,
  ListAttachedUserPoliciesCommand,
  ListGroupPoliciesCommand,
  ListGroupsForUserCommand,
  ListPoliciesCommand,
  ListUserPoliciesCommand,
  PutGroupPolicyCommand,
  PutUserPolicyCommand,
  RemoveUserFromGroupCommand,
} from "@aws-sdk/client-iam";

import {
  AWS_REGION,
  LOCALSTACK_ENDPOINT,
  assertLocalStackReachable,
  createEC2Client,
  createIAMClient,
  createS3Client,
} from "../lib/aws/localstack.ts";

// ---------------------------------------------------------------------------
// Fixture definitions
// ---------------------------------------------------------------------------

/** Insecure fixtures — each should produce at least one finding. */
const VULNERABLE_BUCKET = "cloudsentinel-public-assets";
const VULNERABLE_SG = "cloudsentinel-open-mgmt";
const VULNERABLE_USER = "cloudsentinel-admin-svc";
const WILDCARD_POLICY = "CloudSentinelWildcardAccess";
const INLINE_POLICY = "CloudSentinelPassRoleAnywhere";

/**
 * The group-inheritance fixture.
 *
 * `GROUP_MEMBER_USER` has no attached policies, no inline policies, no access
 * keys, and no console login — inspected on its own it is the most boring
 * account in the environment. Every permission it holds comes from
 * `VULNERABLE_GROUP`, which carries both a managed policy (`*` on `*`) and an
 * inline one granting full `iam:*`.
 *
 * This exists because a scanner that reads only user-level permissions reports
 * this account as clean, which is a false negative — the failure mode where the
 * tool says nothing is wrong and gives the reader no reason to look twice.
 * Seeding it means that path is exercised on every run rather than only in
 * theory.
 */
const VULNERABLE_GROUP = "cloudsentinel-legacy-admins";
const GROUP_INLINE_POLICY = "CloudSentinelGroupIamControl";
const GROUP_MEMBER_USER = "cloudsentinel-group-member";

/** Compliant control group — the rule engine should leave these alone. */
const COMPLIANT_BUCKET = "cloudsentinel-private-logs";
const COMPLIANT_SG = "cloudsentinel-restricted-app";
const COMPLIANT_USER = "cloudsentinel-readonly-svc";

const TAGS = [
  { Key: "Project", Value: "CloudSentinel" },
  { Key: "ManagedBy", Value: "seed-localstack" },
];

/**
 * What each fixture is meant to trip. Printed after seeding, and the checklist
 * the Phase 3 rule engine gets written against.
 */
const EXPECTED_FINDINGS: ReadonlyArray<readonly [resource: string, finding: string]> = [
  [VULNERABLE_BUCKET, "S3 bucket has Block Public Access fully disabled"],
  [VULNERABLE_BUCKET, "S3 bucket policy grants s3:GetObject to Principal '*'"],
  [VULNERABLE_BUCKET, "S3 bucket ACL grants READ to AllUsers"],
  [VULNERABLE_BUCKET, "S3 bucket has versioning disabled"],
  [VULNERABLE_BUCKET, "S3 bucket has no server access logging"],
  [VULNERABLE_SG, "Security group allows 0.0.0.0/0 on tcp/22 (SSH)"],
  [VULNERABLE_SG, "Security group allows 0.0.0.0/0 on tcp/3389 (RDP)"],
  [VULNERABLE_SG, "Security group allows ::/0 on tcp/22 (SSH over IPv6)"],
  [VULNERABLE_USER, "IAM user has an attached policy with Action '*' on Resource '*'"],
  [VULNERABLE_USER, "IAM user has an inline policy allowing unrestricted iam:PassRole"],
  [VULNERABLE_USER, "IAM user has console access but no MFA device"],
  [VULNERABLE_USER, "IAM user has a long-lived access key"],
  [
    GROUP_MEMBER_USER,
    "IAM user inherits Action '*' on Resource '*' through group membership",
  ],
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const log = {
  step: (msg: string) => console.log(`\n\x1b[1m${msg}\x1b[0m`),
  ok: (msg: string) => console.log(`  \x1b[32m+\x1b[0m ${msg}`),
  skip: (msg: string) => console.log(`  \x1b[90m=\x1b[0m ${msg}`),
  gone: (msg: string) => console.log(`  \x1b[33m-\x1b[0m ${msg}`),
  warn: (msg: string) => console.log(`  \x1b[33m!\x1b[0m ${msg}`),
};

/** Runs `fn`, swallowing only the named AWS error codes. */
async function tolerate<T>(
  codes: readonly string[],
  fn: () => Promise<T>,
): Promise<T | undefined> {
  try {
    return await fn();
  } catch (error) {
    const code = (error as { name?: string }).name ?? "";
    if (codes.includes(code)) return undefined;
    throw error;
  }
}

const ALREADY_EXISTS = [
  "BucketAlreadyOwnedByYou",
  "BucketAlreadyExists",
  "EntityAlreadyExists",
  "EntityAlreadyExistsException",
  "InvalidGroup.Duplicate",
  "InvalidPermission.Duplicate",
];

const NOT_FOUND = [
  "NoSuchBucket",
  "NoSuchEntity",
  "NoSuchEntityException",
  "NotFoundException",
  "InvalidGroup.NotFound",
  "InvalidGroupId.NotFound",
];

// ---------------------------------------------------------------------------
// S3
// ---------------------------------------------------------------------------

async function seedBuckets(): Promise<void> {
  const s3 = createS3Client();
  log.step("S3");

  // --- Insecure: world-readable bucket holding plausible-looking data ------
  await tolerate(ALREADY_EXISTS, () =>
    s3.send(new CreateBucketCommand({ Bucket: VULNERABLE_BUCKET })),
  );
  log.ok(`bucket ${VULNERABLE_BUCKET}`);

  await s3.send(
    new PutBucketTaggingCommand({
      Bucket: VULNERABLE_BUCKET,
      Tagging: {
        TagSet: [...TAGS, { Key: "Posture", Value: "intentionally-insecure" }],
      },
    }),
  );

  // Block Public Access must come off before S3 will accept a public policy.
  await s3.send(
    new PutPublicAccessBlockCommand({
      Bucket: VULNERABLE_BUCKET,
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: false,
        IgnorePublicAcls: false,
        BlockPublicPolicy: false,
        RestrictPublicBuckets: false,
      },
    }),
  );
  log.ok("  block public access: fully disabled");

  await s3.send(
    new PutBucketPolicyCommand({
      Bucket: VULNERABLE_BUCKET,
      Policy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "PublicReadGetObject",
            Effect: "Allow",
            Principal: "*",
            Action: "s3:GetObject",
            Resource: `arn:aws:s3:::${VULNERABLE_BUCKET}/*`,
          },
        ],
      }),
    }),
  );
  log.ok("  bucket policy: public s3:GetObject");

  // ACLs only apply when ownership controls allow them.
  const aclApplied = await tolerate(
    [
      "InvalidBucketAclWithObjectOwnership",
      "AccessControlListNotSupported",
      "NotImplemented",
    ],
    async () => {
      await s3.send(
        new PutBucketOwnershipControlsCommand({
          Bucket: VULNERABLE_BUCKET,
          OwnershipControls: { Rules: [{ ObjectOwnership: "ObjectWriter" }] },
        }),
      );
      await s3.send(
        new PutBucketAclCommand({ Bucket: VULNERABLE_BUCKET, ACL: "public-read" }),
      );
      return true;
    },
  );
  if (aclApplied) log.ok("  bucket ACL: public-read");
  else log.warn("  bucket ACL: skipped (unsupported by this LocalStack build)");

  // Versioning and access logging are left off on purpose — both are findings.
  await s3.send(
    new PutObjectCommand({
      Bucket: VULNERABLE_BUCKET,
      Key: "exports/customers.csv",
      Body: "id,email,plan\n1,ada@example.com,enterprise\n2,grace@example.com,pro\n",
      ContentType: "text/csv",
    }),
  );
  log.ok("  object exports/customers.csv (synthetic data)");

  // --- Compliant control ---------------------------------------------------
  await tolerate(ALREADY_EXISTS, () =>
    s3.send(new CreateBucketCommand({ Bucket: COMPLIANT_BUCKET })),
  );
  await s3.send(
    new PutBucketTaggingCommand({
      Bucket: COMPLIANT_BUCKET,
      Tagging: {
        TagSet: [...TAGS, { Key: "Posture", Value: "compliant-control" }],
      },
    }),
  );
  await s3.send(
    new PutPublicAccessBlockCommand({
      Bucket: COMPLIANT_BUCKET,
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true,
        IgnorePublicAcls: true,
        BlockPublicPolicy: true,
        RestrictPublicBuckets: true,
      },
    }),
  );
  await s3.send(
    new PutBucketVersioningCommand({
      Bucket: COMPLIANT_BUCKET,
      VersioningConfiguration: { Status: "Enabled" },
    }),
  );
  // Access logging, pointed at this bucket itself.
  //
  // The control group only demonstrates a zero false-positive baseline if it
  // is clean under *every* rule, and without this the CIS access-logging check
  // would fire on the one bucket that is supposed to be exemplary. Seeding a
  // separate destination bucket would not fix it — that bucket would have no
  // logging either, and so on. A bucket whose entire purpose is holding logs
  // is a legitimate target for its own access logs, which ends the regress.
  //
  // Real AWS additionally requires the target bucket to grant write access to
  // the log delivery group (or an equivalent bucket policy under
  // bucket-owner-enforced ownership). LocalStack does not enforce it, and
  // granting it here would add a permission the fixture does not otherwise
  // need, so it is deliberately left out.
  await s3.send(
    new PutBucketLoggingCommand({
      Bucket: COMPLIANT_BUCKET,
      BucketLoggingStatus: {
        LoggingEnabled: {
          TargetBucket: COMPLIANT_BUCKET,
          TargetPrefix: "access-logs/",
        },
      },
    }),
  );

  log.ok(
    `bucket ${COMPLIANT_BUCKET} (control: PAB on, versioning on, logging on)`,
  );
}

async function destroyBuckets(): Promise<void> {
  const s3 = createS3Client();
  log.step("S3 teardown");

  for (const bucket of [VULNERABLE_BUCKET, COMPLIANT_BUCKET]) {
    const removed = await tolerate(NOT_FOUND, async () => {
      // Versioned buckets need every version *and* delete marker removed.
      for (;;) {
        const listed = await s3.send(
          new ListObjectVersionsCommand({ Bucket: bucket }),
        );
        const objects = [
          ...(listed.Versions ?? []),
          ...(listed.DeleteMarkers ?? []),
        ].map((entry) => ({ Key: entry.Key!, VersionId: entry.VersionId }));

        if (objects.length === 0) break;
        await s3.send(
          new DeleteObjectsCommand({
            Bucket: bucket,
            Delete: { Objects: objects },
          }),
        );
      }
      await s3.send(new DeleteBucketCommand({ Bucket: bucket }));
      return true;
    });
    if (removed) log.gone(`bucket ${bucket}`);
    else log.skip(`bucket ${bucket} (absent)`);
  }
}

// ---------------------------------------------------------------------------
// EC2 security groups
// ---------------------------------------------------------------------------

async function defaultVpcId(ec2: EC2Client): Promise<string> {
  const { Vpcs } = await ec2.send(
    new DescribeVpcsCommand({
      Filters: [{ Name: "isDefault", Values: ["true"] }],
    }),
  );
  const defaultVpc = Vpcs?.[0]?.VpcId;
  if (defaultVpc) return defaultVpc;

  const all = await ec2.send(new DescribeVpcsCommand({}));
  const fallback = all.Vpcs?.[0]?.VpcId;
  if (!fallback) {
    throw new Error("No VPC found in LocalStack; cannot create security groups.");
  }
  return fallback;
}

async function findSecurityGroupId(
  ec2: EC2Client,
  groupName: string,
): Promise<string | undefined> {
  const result = await tolerate(NOT_FOUND, () =>
    ec2.send(
      new DescribeSecurityGroupsCommand({
        Filters: [{ Name: "group-name", Values: [groupName] }],
      }),
    ),
  );
  return result?.SecurityGroups?.[0]?.GroupId;
}

async function seedSecurityGroups(): Promise<void> {
  const ec2 = createEC2Client();
  log.step("EC2 security groups");

  const vpcId = await defaultVpcId(ec2);
  log.skip(`using VPC ${vpcId}`);

  // --- Insecure: management ports exposed to the internet ------------------
  let openGroupId = await findSecurityGroupId(ec2, VULNERABLE_SG);
  if (!openGroupId) {
    const created = await ec2.send(
      new CreateSecurityGroupCommand({
        GroupName: VULNERABLE_SG,
        Description: "CloudSentinel fixture: management ports open to the world",
        VpcId: vpcId,
        TagSpecifications: [{ ResourceType: "security-group", Tags: TAGS }],
      }),
    );
    openGroupId = created.GroupId!;
  }
  log.ok(`${VULNERABLE_SG} (${openGroupId})`);

  const openGroup = openGroupId;
  await tolerate(ALREADY_EXISTS, () =>
    ec2.send(
      new AuthorizeSecurityGroupIngressCommand({
        GroupId: openGroup,
        IpPermissions: [
          {
            IpProtocol: "tcp",
            FromPort: 22,
            ToPort: 22,
            IpRanges: [{ CidrIp: "0.0.0.0/0", Description: "SSH from anywhere" }],
            Ipv6Ranges: [
              { CidrIpv6: "::/0", Description: "SSH from anywhere (IPv6)" },
            ],
          },
          {
            IpProtocol: "tcp",
            FromPort: 3389,
            ToPort: 3389,
            IpRanges: [{ CidrIp: "0.0.0.0/0", Description: "RDP from anywhere" }],
          },
        ],
      }),
    ),
  );
  log.ok("  ingress: tcp/22 + tcp/3389 from 0.0.0.0/0, tcp/22 from ::/0");

  // --- Compliant control ---------------------------------------------------
  let tightGroupId = await findSecurityGroupId(ec2, COMPLIANT_SG);
  if (!tightGroupId) {
    const created = await ec2.send(
      new CreateSecurityGroupCommand({
        GroupName: COMPLIANT_SG,
        Description: "CloudSentinel fixture: HTTPS from the VPC range only",
        VpcId: vpcId,
        TagSpecifications: [{ ResourceType: "security-group", Tags: TAGS }],
      }),
    );
    tightGroupId = created.GroupId!;
  }
  const tightGroup = tightGroupId;
  await tolerate(ALREADY_EXISTS, () =>
    ec2.send(
      new AuthorizeSecurityGroupIngressCommand({
        GroupId: tightGroup,
        IpPermissions: [
          {
            IpProtocol: "tcp",
            FromPort: 443,
            ToPort: 443,
            IpRanges: [{ CidrIp: "10.0.0.0/16", Description: "HTTPS from VPC" }],
          },
        ],
      }),
    ),
  );
  log.ok(`${COMPLIANT_SG} (${tightGroup}) (control: tcp/443 from 10.0.0.0/16)`);
}

async function destroySecurityGroups(): Promise<void> {
  const ec2 = createEC2Client();
  log.step("EC2 teardown");

  for (const name of [VULNERABLE_SG, COMPLIANT_SG]) {
    const groupId = await findSecurityGroupId(ec2, name);
    if (!groupId) {
      log.skip(`${name} (absent)`);
      continue;
    }
    await tolerate(NOT_FOUND, () =>
      ec2.send(new DeleteSecurityGroupCommand({ GroupId: groupId })),
    );
    log.gone(`${name} (${groupId})`);
  }
}

// ---------------------------------------------------------------------------
// IAM
// ---------------------------------------------------------------------------

const WILDCARD_POLICY_DOC = JSON.stringify({
  Version: "2012-10-17",
  Statement: [
    { Sid: "AllowEverything", Effect: "Allow", Action: "*", Resource: "*" },
  ],
});

/**
 * Inline policy on the group. Deliberately different in shape from the managed
 * `*:*` policy so that both resolution paths the collector uses —
 * ListAttachedGroupPolicies (managed, via GetPolicyVersion) and
 * ListGroupPolicies (inline, via GetGroupPolicy) — are exercised by the
 * fixtures rather than only one of them.
 */
const GROUP_IAM_CONTROL_DOC = JSON.stringify({
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "GroupWideIamControl",
      Effect: "Allow",
      Action: ["iam:*", "sts:AssumeRole"],
      Resource: "*",
    },
  ],
});

const PASS_ROLE_DOC = JSON.stringify({
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "PassAnyRole",
      Effect: "Allow",
      Action: ["iam:PassRole", "iam:CreatePolicyVersion", "iam:AttachUserPolicy"],
      Resource: "*",
    },
  ],
});

async function findLocalPolicyArn(
  iam: IAMClient,
  policyName: string,
): Promise<string | undefined> {
  let marker: string | undefined;
  do {
    const page = await iam.send(
      new ListPoliciesCommand({ Scope: "Local", Marker: marker }),
    );
    const hit = page.Policies?.find((p) => p.PolicyName === policyName);
    if (hit?.Arn) return hit.Arn;
    marker = page.IsTruncated ? page.Marker : undefined;
  } while (marker);
  return undefined;
}

async function seedIam(): Promise<void> {
  const iam = createIAMClient();
  log.step("IAM");

  // --- Insecure: over-privileged human-usable account, no MFA --------------
  await tolerate(ALREADY_EXISTS, () =>
    iam.send(new CreateUserCommand({ UserName: VULNERABLE_USER, Tags: TAGS })),
  );
  log.ok(`user ${VULNERABLE_USER}`);

  let policyArn = await findLocalPolicyArn(iam, WILDCARD_POLICY);
  if (!policyArn) {
    const created = await iam.send(
      new CreatePolicyCommand({
        PolicyName: WILDCARD_POLICY,
        PolicyDocument: WILDCARD_POLICY_DOC,
        Description: "CloudSentinel fixture: Action '*' on Resource '*'",
      }),
    );
    policyArn = created.Policy!.Arn!;
  }
  await tolerate(ALREADY_EXISTS, () =>
    iam.send(
      new AttachUserPolicyCommand({
        UserName: VULNERABLE_USER,
        PolicyArn: policyArn,
      }),
    ),
  );
  log.ok(`  attached managed policy ${WILDCARD_POLICY} (*:*)`);

  await iam.send(
    new PutUserPolicyCommand({
      UserName: VULNERABLE_USER,
      PolicyName: INLINE_POLICY,
      PolicyDocument: PASS_ROLE_DOC,
    }),
  );
  log.ok(`  inline policy ${INLINE_POLICY} (privilege-escalation path)`);

  // A console login profile with no MFA device is what makes the "no MFA"
  // finding meaningful — a user who cannot sign in has nothing to protect.
  const loginCreated = await tolerate(ALREADY_EXISTS, () =>
    iam.send(
      new CreateLoginProfileCommand({
        UserName: VULNERABLE_USER,
        Password: "Fixture-Console-Pw-1!",
        PasswordResetRequired: false,
      }),
    ),
  );
  log.ok(
    loginCreated
      ? "  console login profile created, no MFA device enrolled"
      : "  console login profile already present, no MFA device enrolled",
  );

  // Only mint a key if the user has none, so re-runs do not pile them up.
  const { AccessKeyMetadata } = await iam.send(
    new ListAccessKeysCommand({ UserName: VULNERABLE_USER }),
  );
  if ((AccessKeyMetadata ?? []).length === 0) {
    const key = await iam.send(
      new CreateAccessKeyCommand({ UserName: VULNERABLE_USER }),
    );
    // Secret intentionally not logged, even though it is a throwaway.
    log.ok(`  access key ${key.AccessKey!.AccessKeyId} (secret not printed)`);
  } else {
    log.skip(`  access key already exists (${AccessKeyMetadata![0]!.AccessKeyId})`);
  }

  // --- Insecure: privilege inherited through a group -----------------------
  // The point of this fixture is that the user below is unremarkable in every
  // way a user-level check can see. Only following the group membership reveals
  // that it holds full administrative access.
  await tolerate(ALREADY_EXISTS, () =>
    iam.send(new CreateGroupCommand({ GroupName: VULNERABLE_GROUP })),
  );
  log.ok(`group ${VULNERABLE_GROUP}`);

  await tolerate(ALREADY_EXISTS, () =>
    iam.send(
      new AttachGroupPolicyCommand({
        GroupName: VULNERABLE_GROUP,
        PolicyArn: policyArn,
      }),
    ),
  );
  log.ok(`  attached managed policy ${WILDCARD_POLICY} (*:*)`);

  await iam.send(
    new PutGroupPolicyCommand({
      GroupName: VULNERABLE_GROUP,
      PolicyName: GROUP_INLINE_POLICY,
      PolicyDocument: GROUP_IAM_CONTROL_DOC,
    }),
  );
  log.ok(`  inline policy ${GROUP_INLINE_POLICY} (iam:* on *)`);

  await tolerate(ALREADY_EXISTS, () =>
    iam.send(new CreateUserCommand({ UserName: GROUP_MEMBER_USER, Tags: TAGS })),
  );
  // AddUserToGroup is naturally idempotent — re-adding an existing member is a
  // no-op rather than an error — so no tolerate wrapper is needed here.
  await iam.send(
    new AddUserToGroupCommand({
      GroupName: VULNERABLE_GROUP,
      UserName: GROUP_MEMBER_USER,
    }),
  );
  log.ok(
    `user ${GROUP_MEMBER_USER} (no direct policies; admin only via ${VULNERABLE_GROUP})`,
  );

  // --- Compliant control: scoped, no console, no keys ----------------------
  await tolerate(ALREADY_EXISTS, () =>
    iam.send(new CreateUserCommand({ UserName: COMPLIANT_USER, Tags: TAGS })),
  );
  await iam.send(
    new PutUserPolicyCommand({
      UserName: COMPLIANT_USER,
      PolicyName: "CloudSentinelReadOnlyLogs",
      PolicyDocument: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "ReadLogsBucketOnly",
            Effect: "Allow",
            Action: ["s3:GetObject", "s3:ListBucket"],
            Resource: [
              `arn:aws:s3:::${COMPLIANT_BUCKET}`,
              `arn:aws:s3:::${COMPLIANT_BUCKET}/*`,
            ],
          },
        ],
      }),
    }),
  );
  log.ok(`user ${COMPLIANT_USER} (control: least-privilege, no console, no keys)`);
}

async function destroyIam(): Promise<void> {
  const iam = createIAMClient();
  log.step("IAM teardown");

  for (const userName of [VULNERABLE_USER, GROUP_MEMBER_USER, COMPLIANT_USER]) {
    const attached = await tolerate(NOT_FOUND, () =>
      iam.send(new ListAttachedUserPoliciesCommand({ UserName: userName })),
    );
    if (!attached) {
      log.skip(`user ${userName} (absent)`);
      continue;
    }

    // A user cannot be deleted until every dependency is removed.
    for (const policy of attached.AttachedPolicies ?? []) {
      await tolerate(NOT_FOUND, () =>
        iam.send(
          new DetachUserPolicyCommand({
            UserName: userName,
            PolicyArn: policy.PolicyArn!,
          }),
        ),
      );
    }

    const inline = await tolerate(NOT_FOUND, () =>
      iam.send(new ListUserPoliciesCommand({ UserName: userName })),
    );
    for (const policyName of inline?.PolicyNames ?? []) {
      await tolerate(NOT_FOUND, () =>
        iam.send(
          new DeleteUserPolicyCommand({ UserName: userName, PolicyName: policyName }),
        ),
      );
    }

    const keys = await tolerate(NOT_FOUND, () =>
      iam.send(new ListAccessKeysCommand({ UserName: userName })),
    );
    for (const key of keys?.AccessKeyMetadata ?? []) {
      await tolerate(NOT_FOUND, () =>
        iam.send(
          new DeleteAccessKeyCommand({
            UserName: userName,
            AccessKeyId: key.AccessKeyId!,
          }),
        ),
      );
    }

    // Group membership is also a dependency: IAM refuses to delete a user who
    // still belongs to a group.
    const memberships = await tolerate(NOT_FOUND, () =>
      iam.send(new ListGroupsForUserCommand({ UserName: userName })),
    );
    for (const group of memberships?.Groups ?? []) {
      if (!group.GroupName) continue;
      await tolerate(NOT_FOUND, () =>
        iam.send(
          new RemoveUserFromGroupCommand({
            UserName: userName,
            GroupName: group.GroupName!,
          }),
        ),
      );
    }

    await tolerate(NOT_FOUND, () =>
      iam.send(new DeleteLoginProfileCommand({ UserName: userName })),
    );
    await tolerate(NOT_FOUND, () =>
      iam.send(new DeleteUserCommand({ UserName: userName })),
    );
    log.gone(`user ${userName}`);
  }

  // The group must go before the managed policy: IAM refuses to delete a
  // policy that is still attached to anything.
  const groupAttached = await tolerate(NOT_FOUND, () =>
    iam.send(new ListAttachedGroupPoliciesCommand({ GroupName: VULNERABLE_GROUP })),
  );
  if (groupAttached) {
    for (const policy of groupAttached.AttachedPolicies ?? []) {
      if (!policy.PolicyArn) continue;
      await tolerate(NOT_FOUND, () =>
        iam.send(
          new DetachGroupPolicyCommand({
            GroupName: VULNERABLE_GROUP,
            PolicyArn: policy.PolicyArn!,
          }),
        ),
      );
    }

    const groupInline = await tolerate(NOT_FOUND, () =>
      iam.send(new ListGroupPoliciesCommand({ GroupName: VULNERABLE_GROUP })),
    );
    for (const policyName of groupInline?.PolicyNames ?? []) {
      await tolerate(NOT_FOUND, () =>
        iam.send(
          new DeleteGroupPolicyCommand({
            GroupName: VULNERABLE_GROUP,
            PolicyName: policyName,
          }),
        ),
      );
    }

    await tolerate(NOT_FOUND, () =>
      iam.send(new DeleteGroupCommand({ GroupName: VULNERABLE_GROUP })),
    );
    log.gone(`group ${VULNERABLE_GROUP}`);
  } else {
    log.skip(`group ${VULNERABLE_GROUP} (absent)`);
  }

  const policyArn = await findLocalPolicyArn(iam, WILDCARD_POLICY);
  if (policyArn) {
    await tolerate(NOT_FOUND, () =>
      iam.send(new DeletePolicyCommand({ PolicyArn: policyArn })),
    );
    log.gone(`managed policy ${WILDCARD_POLICY}`);
  } else {
    log.skip(`managed policy ${WILDCARD_POLICY} (absent)`);
  }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

function printPlan(): void {
  console.log("\nFixture plan — expected findings:\n");
  let current = "";
  for (const [resource, finding] of EXPECTED_FINDINGS) {
    if (resource !== current) {
      console.log(`  ${resource}`);
      current = resource;
    }
    console.log(`    - ${finding}`);
  }
  console.log(
    "\n  Compliant controls (should produce no findings):\n" +
      `    ${COMPLIANT_BUCKET}, ${COMPLIANT_SG}, ${COMPLIANT_USER}\n`,
  );
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes("--list")) {
    printPlan();
    return;
  }

  const teardown = args.includes("--teardown");

  console.log(
    `CloudSentinel fixtures -> ${LOCALSTACK_ENDPOINT} (${AWS_REGION})\n` +
      `Mode: ${teardown ? "teardown" : "provision"}`,
  );
  await assertLocalStackReachable();

  if (teardown) {
    // Reverse of creation order: IAM policies reference the buckets by ARN.
    await destroyIam();
    await destroySecurityGroups();
    await destroyBuckets();
    console.log("\nTeardown complete.\n");
    return;
  }

  await seedBuckets();
  await seedSecurityGroups();
  await seedIam();

  printPlan();
  console.log(
    "Seed complete. Spot-check with:\n" +
      `  awslocal s3api get-bucket-policy --bucket ${VULNERABLE_BUCKET}\n` +
      `  awslocal ec2 describe-security-groups --group-names ${VULNERABLE_SG}\n` +
      `  awslocal iam list-attached-user-policies --user-name ${VULNERABLE_USER}\n`,
  );
}

main().catch((error: unknown) => {
  console.error(
    `\n\x1b[31mFailed:\x1b[0m ${
      error instanceof Error ? error.message : String(error)
    }`,
  );
  process.exitCode = 1;
});
