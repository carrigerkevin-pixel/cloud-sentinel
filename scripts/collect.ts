/**
 * CloudSentinel — collector entry point.
 *
 * Runs all three collectors against the configured LocalStack environment and
 * emits a single {@link ResourceInventory}: one coherent, point-in-time
 * snapshot of the cloud resources CloudSentinel understands.
 *
 *   npm run collect                  human-readable summary
 *   npm run collect -- --json        raw inventory JSON on stdout, for piping
 *   npm run collect -- --out <file>  write the inventory to a file
 *
 * Where it sits in the architecture: this is the seam between stage one
 * (collection) and stage two (the rule engine). Writing an inventory to disk
 * with `--out` lets the rule engine be developed and tested against a fixed
 * snapshot, with no LocalStack container running at all — which also means the
 * rule engine's tests can run in CI, where there is no AWS to talk to.
 *
 *   LocalStack --> [ collect ] --> inventory.json --> rule engine --> findings
 *
 * SECURITY: read-only from end to end. Every command the three collectors issue
 * is a `List*`, `Get*`, or `Describe*`, and lib/aws/localstack.ts refuses to
 * build a client for any endpoint that is not loopback. Running this cannot
 * change the environment it audits.
 *
 * Exit status: non-zero if any collector recorded a {@link CollectionError}.
 * A scan that could not see everything must not report success — once this runs
 * in CI, a silent partial scan would be indistinguishable from a clean one, and
 * "we found no problems" is a very different claim from "we failed to look".
 */

import { writeFile } from "node:fs/promises";

import {
  AWS_REGION,
  LOCALSTACK_ENDPOINT,
  assertLocalStackReachable,
} from "../lib/aws/localstack.ts";
import { collectSecurityGroups } from "../lib/collectors/ec2.ts";
import { collectIamUsers } from "../lib/collectors/iam.ts";
import { collectS3Buckets } from "../lib/collectors/s3.ts";
import type { Resource, ResourceInventory } from "../lib/types/resource.ts";

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

/**
 * ANSI colour codes, matching the palette the seed script uses so the two
 * tools look like parts of the same product.
 */
const style = {
  bold: (text: string) => `\x1b[1m${text}\x1b[0m`,
  dim: (text: string) => `\x1b[90m${text}\x1b[0m`,
  red: (text: string) => `\x1b[31m${text}\x1b[0m`,
  yellow: (text: string) => `\x1b[33m${text}\x1b[0m`,
  green: (text: string) => `\x1b[32m${text}\x1b[0m`,
};

/**
 * Renders the observed facts about one resource as short `key=value` chips.
 *
 * This is a *description*, not a verdict. The collector's contract is to report
 * what AWS said and leave judgement to the rule engine, so nothing here says
 * "insecure" or "compliant" — it prints `publicAccessBlock=none` and lets the
 * reader (and, later, a rule) draw the conclusion. Keeping that boundary
 * visible even in console output makes it harder to erode by accident.
 *
 * The fields chosen are the ones the twelve seeded findings depend on, so a
 * glance at this output is enough to confirm the collector gathered what the
 * rule engine will need.
 */
function describe(resource: Resource): string[] {
  switch (resource.type) {
    case "s3_bucket": {
      const { config } = resource;
      const pab = config.publicAccessBlock;
      const publicGrants = config.aclGrants.filter((grant) =>
        (grant.granteeId ?? "").includes("acs.amazonaws.com/groups/global"),
      ).length;

      // All four flags off must be reported distinctly from "some are off".
      // An earlier version of this collapsed both into "partial", which
      // understated the single worst case a bucket can be in — and a security
      // tool that rounds the most severe state toward the milder label is
      // wrong in the one direction that matters. The count is shown for the
      // in-between case so the output says how much protection is left.
      const pabFlags =
        pab === null
          ? null
          : [
              pab.blockPublicAcls,
              pab.ignorePublicAcls,
              pab.blockPublicPolicy,
              pab.restrictPublicBuckets,
            ];
      const pabOn = pabFlags?.filter(Boolean).length ?? 0;

      return [
        `blockPublicAccess=${
          pabFlags === null
            ? "none"
            : pabOn === 4
              ? "all-on"
              : pabOn === 0
                ? "all-off"
                : `partial(${pabOn}/4)`
        }`,
        `policyStatements=${config.policy?.Statement.length ?? 0}`,
        `publicAclGrants=${publicGrants}`,
        `versioning=${config.versioning}`,
        `logging=${config.loggingEnabled ? "on" : "off"}`,
        `encryption=${config.encryptionAlgorithm ?? "none"}`,
      ];
    }
    case "security_group": {
      const { config } = resource;
      // "Open to the world" counts both IP families: a group locked down on
      // IPv4 but wide open on IPv6 is wide open.
      const worldOpen = config.ingressRules.filter(
        (rule) =>
          rule.ipv4Ranges.includes("0.0.0.0/0") || rule.ipv6Ranges.includes("::/0"),
      ).length;
      return [
        `vpc=${config.vpcId ?? "none"}`,
        `ingressRules=${config.ingressRules.length}`,
        `ingressFromAnywhere=${worldOpen}`,
        `egressRules=${config.egressRules.length}`,
      ];
    }
    case "iam_user": {
      const { config } = resource;
      return [
        `console=${config.hasConsoleAccess ? "yes" : "no"}`,
        `mfaDevices=${config.mfaDeviceIds.length}`,
        `accessKeys=${config.accessKeys.length}`,
        `managedPolicies=${config.attachedPolicies.length}`,
        `inlinePolicies=${config.inlinePolicies.length}`,
        `groups=${config.groupNames.length}`,
      ];
    }
  }
}

/** Section headings, in the order they are printed. */
const TYPE_HEADINGS = {
  s3_bucket: "S3 buckets",
  security_group: "EC2 security groups",
  iam_user: "IAM users",
} as const;

/** Prints the inventory as a grouped, human-readable summary. */
function printSummary(inventory: ResourceInventory): void {
  for (const [type, heading] of Object.entries(TYPE_HEADINGS)) {
    const matching = inventory.resources.filter(
      (resource) => resource.type === type,
    );
    console.log(`\n${style.bold(heading)} (${matching.length})`);

    if (matching.length === 0) {
      console.log(style.dim("  none found"));
      continue;
    }

    for (const resource of matching) {
      console.log(`  ${style.bold(resource.name)} ${style.dim(resource.region)}`);
      console.log(`    ${style.dim(describe(resource).join("  "))}`);

      // Printed in warning colour rather than dimmed with the rest, because
      // the values shown above for these fields are defaults standing in for
      // data that was never read. Anything concluded from them is unreliable,
      // and that has to be visible in the terminal — not only in the JSON.
      if (resource.unobserved.length > 0) {
        console.log(
          `    ${style.yellow(`unobserved: ${resource.unobserved.join(", ")}`)}`,
        );
      }
    }
  }

  if (inventory.errors.length > 0) {
    console.log(`\n${style.bold(style.yellow("Collection errors"))}`);
    for (const error of inventory.errors) {
      const target = error.resourceName ?? "(service)";
      console.log(
        `  ${style.yellow("!")} ${error.operation} on ${target}: ${error.message}`,
      );
    }
    console.log(
      style.dim(
        "\n  Findings derived from missing data may be unreliable — a failed\n" +
          "  observation is not the same as an absent setting.",
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

function printUsage(): void {
  console.log(
    "\nUsage: npm run collect [-- <options>]\n\n" +
      "  --json          print the raw inventory as JSON (no summary)\n" +
      "  --out <file>    write the inventory JSON to <file>\n" +
      "  --help          show this message\n",
  );
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes("--help")) {
    printUsage();
    return;
  }

  const asJson = args.includes("--json");
  const outIndex = args.indexOf("--out");
  const outPath = outIndex === -1 ? null : args[outIndex + 1];

  if (outIndex !== -1 && !outPath) {
    throw new Error("--out requires a file path, e.g. --out inventory.json");
  }

  // Progress goes to stderr, never stdout, so that `--json` output stays a
  // clean stream that can be piped into jq or redirected to a file.
  if (!asJson) {
    console.error(
      `CloudSentinel collector -> ${LOCALSTACK_ENDPOINT} (${AWS_REGION})`,
    );
  }

  // Fail fast with one clear message if the container is not up, rather than
  // letting three collectors each produce their own connection stack trace.
  await assertLocalStackReachable();

  // One timestamp for the entire scan. Generated here and passed down rather
  // than defaulted inside each collector, because three separately-generated
  // timestamps would make a single snapshot look like three different readings
  // — and any later "what changed between scans" comparison depends on a scan
  // having exactly one time.
  const collectedAt = new Date().toISOString();

  // The three services are unrelated, so their collectors run concurrently.
  const [s3Result, ec2Result, iamResult] = await Promise.all([
    collectS3Buckets(collectedAt),
    collectSecurityGroups(collectedAt),
    collectIamUsers(collectedAt),
  ]);

  const inventory: ResourceInventory = {
    collectedAt,
    // Recorded so a saved inventory can never be mistaken for one taken from a
    // different environment — an inventory file outlives the shell that made it.
    endpoint: LOCALSTACK_ENDPOINT,
    region: AWS_REGION,
    resources: [
      ...s3Result.resources,
      ...ec2Result.resources,
      ...iamResult.resources,
    ],
    errors: [...s3Result.errors, ...ec2Result.errors, ...iamResult.errors],
  };

  if (outPath) {
    await writeFile(outPath, `${JSON.stringify(inventory, null, 2)}\n`, "utf8");
    if (!asJson) console.error(style.green(`\nWrote ${outPath}`));
  }

  if (asJson) {
    console.log(JSON.stringify(inventory, null, 2));
  } else {
    printSummary(inventory);
    const partial = inventory.resources.filter(
      (resource) => resource.unobserved.length > 0,
    ).length;
    console.log(
      `\n${style.bold("Total")}: ${inventory.resources.length} resources, ` +
        `${inventory.errors.length} errors, ` +
        `${partial} partially observed  ${style.dim(collectedAt)}\n`,
    );
  }

  // A partial scan is not a successful scan. Signalling this through the exit
  // code is what lets CI, or any script wrapping this one, tell the difference
  // between "nothing was wrong" and "we could not check".
  if (inventory.errors.length > 0) process.exitCode = 1;
}

main().catch((error: unknown) => {
  console.error(
    `\n${style.red("Failed:")} ${
      error instanceof Error ? error.message : String(error)
    }`,
  );
  process.exitCode = 1;
});
