/**
 * CloudSentinel — tests for the bounded concurrency helper.
 *
 * Run with `npm test`. Pure logic, no network.
 *
 * The cap is the whole reason this helper exists, and it is invisible in
 * ordinary use — a scan against LocalStack behaves identically whether the
 * limit is 8 or 8,000. That makes it exactly the kind of property that can be
 * broken by a refactor without anyone noticing until a scan against a real
 * account falls over. So the tests observe concurrency directly, by tracking
 * how many tasks are in flight at once, rather than inferring it from timing.
 */

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { collectorConcurrency, mapWithConcurrency } from "./concurrency.ts";

/** Resolves after the current round of microtasks, without using timers. */
function tick(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

describe("mapWithConcurrency", () => {
  test("never exceeds the limit", async () => {
    let inFlight = 0;
    let peak = 0;

    await mapWithConcurrency([...Array(20).keys()], 3, async (value) => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await tick();
      inFlight -= 1;
      return value;
    });

    assert.equal(peak, 3);
  });

  test("preserves input order regardless of completion order", async () => {
    // The first task finishes last. Results must still come back in input
    // order — callers index into this array and match it against their input,
    // so completion-order results would be a subtle and nasty bug.
    const results = await mapWithConcurrency([0, 1, 2, 3], 4, async (value) => {
      const delay = value === 0 ? 5 : 1;
      for (let i = 0; i < delay; i += 1) await tick();
      return value * 10;
    });

    assert.deepEqual(results, [0, 10, 20, 30]);
  });

  test("passes the index to the callback", async () => {
    const seen = await mapWithConcurrency(["a", "b", "c"], 2, async (item, i) =>
      `${i}:${item}`,
    );

    assert.deepEqual(seen, ["0:a", "1:b", "2:c"]);
  });

  test("returns an empty array for empty input without calling the callback", async () => {
    let calls = 0;
    const results = await mapWithConcurrency([], 4, async () => {
      calls += 1;
      return 1;
    });

    assert.deepEqual(results, []);
    assert.equal(calls, 0);
  });

  test("runs everything when the limit exceeds the input length", async () => {
    const results = await mapWithConcurrency([1, 2], 100, async (n) => n + 1);

    assert.deepEqual(results, [2, 3]);
  });

  test("treats a limit below 1 as 1 rather than deadlocking", async () => {
    // A zero limit would spawn no workers and hang forever. Clamping keeps a
    // bad configuration value from silently stalling an entire scan.
    const results = await mapWithConcurrency([1, 2, 3], 0, async (n) => n * 2);

    assert.deepEqual(results, [2, 4, 6]);
  });

  test("propagates a rejection instead of swallowing it", async () => {
    // The collectors catch their own per-resource failures, so a rejection
    // reaching here means a genuine programming error. It should surface.
    await assert.rejects(
      () =>
        mapWithConcurrency([1, 2, 3], 2, async (n) => {
          if (n === 2) throw new Error("boom");
          return n;
        }),
      /boom/,
    );
  });
});

describe("collectorConcurrency", () => {
  /** Runs `fn` with COLLECTOR_CONCURRENCY set, restoring it afterwards. */
  function withEnv(value: string | undefined, fn: () => void): void {
    const previous = process.env.COLLECTOR_CONCURRENCY;
    if (value === undefined) delete process.env.COLLECTOR_CONCURRENCY;
    else process.env.COLLECTOR_CONCURRENCY = value;
    try {
      fn();
    } finally {
      if (previous === undefined) delete process.env.COLLECTOR_CONCURRENCY;
      else process.env.COLLECTOR_CONCURRENCY = previous;
    }
  }

  test("defaults to 8 when unset", () => {
    withEnv(undefined, () => assert.equal(collectorConcurrency(), 8));
  });

  test("reads a valid positive integer", () => {
    withEnv("16", () => assert.equal(collectorConcurrency(), 16));
  });

  test("falls back to the default on invalid input rather than throwing", () => {
    // A typo in an environment variable should not abort a security scan.
    withEnv("not-a-number", () => assert.equal(collectorConcurrency(), 8));
    withEnv("0", () => assert.equal(collectorConcurrency(), 8));
    withEnv("-4", () => assert.equal(collectorConcurrency(), 8));
  });
});
