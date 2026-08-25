/**
 * CloudSentinel — inventory assembly.
 *
 * Runs all three collectors and merges their output into one coherent
 * {@link ResourceInventory}. This is the seam between the three per-service
 * collectors and everything downstream of them.
 *
 *   [ s3 | ec2 | iam collectors ] --> [ collectInventory ] --> ResourceInventory
 *                                                                   |
 *                                              scripts/collect.ts <--+--> scripts/scan.ts
 *
 * Why this is its own module rather than living in scripts/collect.ts: both the
 * collector CLI and the scanner CLI need a live inventory, and scripts are not
 * importable — scripts/collect.ts calls `main()` at module scope, so importing
 * it to reuse its logic would run it. Extracting the assembly here lets both
 * entry points share one definition of what a scan actually is, so they can
 * never drift into collecting slightly different things.
 *
 * SECURITY: read-only end to end. Every command the three collectors issue is a
 * `List*`, `Get*`, or `Describe*`, and lib/aws/localstack.ts refuses to build a
 * client for any endpoint that is not loopback.
 */

import {
  AWS_REGION,
  LOCALSTACK_ENDPOINT,
  assertLocalStackReachable,
} from "../aws/localstack.ts";
import type { ResourceInventory } from "../types/resource.ts";
import { collectSecurityGroups } from "./ec2.ts";
import { collectIamUsers } from "./iam.ts";
import { collectS3Buckets } from "./s3.ts";

/**
 * Collects a complete, point-in-time inventory from the configured LocalStack
 * environment.
 *
 * @param options.checkReachable - when true (the default), verifies LocalStack
 *   is up before starting, so an unreachable container produces one clear
 *   message rather than three separate connection stack traces. Disabled in
 *   tests that supply their own doubles.
 * @returns the merged inventory. Never throws for a per-resource failure —
 *   those are recorded in `errors`, because partial failure is the expected
 *   case in a real account and aborting the whole scan over one throttled API
 *   call would make the tool useless. It *does* throw if LocalStack is
 *   unreachable, since there is nothing to collect at all in that case.
 */
export async function collectInventory(
  options: { checkReachable?: boolean } = {},
): Promise<ResourceInventory> {
  if (options.checkReachable !== false) {
    await assertLocalStackReachable();
  }

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

  return {
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
}
