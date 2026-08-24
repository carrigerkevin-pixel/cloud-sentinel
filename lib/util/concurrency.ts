/**
 * CloudSentinel — bounded concurrency helper.
 *
 * Where it sits in the architecture: a small utility used by the collectors to
 * keep a scan from issuing every AWS request at once.
 *
 * Why it exists: `Promise.all(items.map(fn))` starts every task immediately.
 * With eight resources that is fine, and it is what the collectors did first.
 * With five hundred S3 buckets it is not — each bucket fans out to eight detail
 * calls, so the naive version would put roughly four thousand HTTP requests in
 * flight simultaneously. That exhausts the socket pool, and it provokes the
 * very API throttling that then has to be retried, turning a scan that should
 * take seconds into one that takes minutes or fails outright.
 *
 * The fix is a cap on how many tasks run at once. Note that this is a
 * *concurrency* limit, not a rate limit: it bounds simultaneous work, it does
 * not pace requests per second. Rate control is handled at the client level by
 * the AWS SDK's adaptive retry mode, configured in lib/aws/localstack.ts —
 * the two mechanisms address different problems and are both needed.
 */

/**
 * Reads the collector's concurrency limit from the environment.
 *
 * Exposed as `COLLECTOR_CONCURRENCY` so a scan of a large account can be tuned
 * without a code change. The default of 8 is deliberately conservative: a
 * security scan is not latency-critical, and being a polite API citizen matters
 * more than finishing a few seconds sooner.
 *
 * @returns The configured limit, or 8 when the variable is unset, unparseable,
 *          or not a positive integer. Invalid input falls back to the default
 *          rather than throwing — a typo in an env var should not abort a scan.
 */
export function collectorConcurrency(): number {
  const raw = process.env.COLLECTOR_CONCURRENCY;
  if (!raw) return 8;

  const parsed = Number.parseInt(raw, 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : 8;
}

/**
 * Maps over `items` with at most `limit` tasks running at once.
 *
 * A drop-in replacement for `Promise.all(items.map(fn))` that adds the cap.
 * Behaviour worth knowing:
 *
 *   - **Order is preserved.** Results line up with the input by index, not by
 *     completion time. Callers sort and match on this, and a result array
 *     silently reordered by whichever request finished first would be a
 *     miserable bug to track down.
 *   - **Rejections propagate.** If `fn` throws, this rejects, exactly like
 *     `Promise.all`. The collectors rely on that never happening in practice —
 *     they catch per-resource failures internally and record them as
 *     `CollectionError`s — but a genuine programming error should still
 *     surface loudly rather than be swallowed here.
 *   - **A limit at or above `items.length` behaves like `Promise.all`**, so
 *     there is no penalty for small inputs.
 *
 * The implementation runs `limit` workers that pull from a shared cursor,
 * rather than slicing the input into fixed batches. Batching would stall on the
 * slowest task in each batch before starting the next one; workers keep every
 * slot busy as soon as it frees up, which matters when one bucket happens to be
 * much slower than its neighbours.
 *
 * @param items Inputs to map over.
 * @param limit Maximum tasks in flight. Values below 1 are treated as 1.
 * @param fn    Called with each item and its index.
 * @returns Results in input order.
 */
export async function mapWithConcurrency<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  if (items.length === 0) return [];

  const effectiveLimit = Math.max(1, Math.min(limit, items.length));
  const results = new Array<R>(items.length);

  // Shared cursor. Safe without a lock because JavaScript is single-threaded:
  // the read-and-increment below cannot be interrupted partway, so two workers
  // can never claim the same index.
  let cursor = 0;

  async function worker(): Promise<void> {
    for (;;) {
      const index = cursor++;
      if (index >= items.length) return;
      results[index] = await fn(items[index]!, index);
    }
  }

  await Promise.all(Array.from({ length: effectiveLimit }, () => worker()));

  return results;
}
