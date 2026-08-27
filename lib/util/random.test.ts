/**
 * CloudSentinel — tests for the seeded pseudo-random number generator.
 *
 * Run with `npm test`. Pure logic, no network, no filesystem.
 *
 * The property under test is the one the whole ML layer leans on:
 * *reproducibility*. Everything downstream — the committed CloudTrail fixture,
 * the labelled attack scenarios, the detector's threshold — is only meaningful
 * if the same seed yields the same numbers. So the first suite below pins exact
 * values rather than merely asserting "two runs agree": a refactor that swapped
 * the algorithm for a different-but-still-deterministic one would pass a
 * self-consistency check while silently invalidating every fixture in the
 * repository.
 *
 * The distribution tests use generous tolerances on purpose. They exist to
 * catch a generator that is outright broken (always returns 0.5, never returns
 * the top of a range, produces NaN), not to certify statistical quality. A
 * tight statistical bound on a fixed seed tests nothing except that the bound
 * was tuned to that seed.
 */

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { createRandom } from "./random.ts";

describe("createRandom — determinism", () => {
  test("the same seed produces the same sequence", () => {
    const first = createRandom("cloudsentinel");
    const second = createRandom("cloudsentinel");

    const a = Array.from({ length: 50 }, () => first.next());
    const b = Array.from({ length: 50 }, () => second.next());

    assert.deepEqual(a, b);
  });

  test("different seeds produce different sequences", () => {
    // Two seeds differing by one character. FNV-1a avalanches, so the streams
    // must be unrelated — a weak seed hash would produce near-identical runs
    // here, which would make "regenerate the fixture with a new seed" a no-op.
    const a = createRandom("run-1");
    const b = createRandom("run-2");

    const first = Array.from({ length: 20 }, () => a.next());
    const second = Array.from({ length: 20 }, () => b.next());

    assert.notDeepEqual(first, second);
  });

  test("a numeric seed is accepted and is also stable", () => {
    const a = createRandom(12345);
    const b = createRandom(12345);

    assert.equal(a.next(), b.next());
  });

  test("the empty string is a valid seed", () => {
    // Guards the FNV loop's zero-iteration case: it must return the offset
    // basis rather than NaN or 0.
    const value = createRandom("").next();

    assert.ok(Number.isFinite(value));
    assert.ok(value >= 0 && value < 1);
  });

  test("generators do not share state", () => {
    // Two independent generators from the same seed must not interfere. If
    // state were module-level rather than per-instance, drawing from one would
    // advance the other, and the log generator — which uses several — would
    // produce different output depending on call ordering elsewhere.
    const a = createRandom("shared");
    const b = createRandom("shared");

    a.next();
    a.next();
    a.next();

    assert.equal(createRandom("shared").next(), b.next());
  });

  test("pins the exact first values for the project seed", () => {
    // A change to these numbers means every committed fixture generated from
    // this seed is now stale. That is a decision to make deliberately, not to
    // discover from a confusing diff — so it fails here first, loudly.
    const random = createRandom("cloudsentinel");
    const values = Array.from({ length: 3 }, () =>
      Number(random.next().toFixed(12)),
    );

    assert.deepEqual(values, [0.243174263276, 0.07910846523, 0.587180353235]);
  });
});

describe("createRandom — int", () => {
  test("stays within the inclusive range", () => {
    const random = createRandom("int-range");

    for (let i = 0; i < 1000; i += 1) {
      const value = random.int(5, 10);
      assert.ok(value >= 5 && value <= 10, `out of range: ${value}`);
      assert.ok(Number.isInteger(value), `not an integer: ${value}`);
    }
  });

  test("actually reaches both endpoints", () => {
    // The classic off-by-one: `min + floor(next() * (max - min))` never returns
    // `max`. Over 500 draws from a 3-wide range, missing an endpoint is not
    // luck.
    const random = createRandom("endpoints");
    const seen = new Set<number>();

    for (let i = 0; i < 500; i += 1) seen.add(random.int(1, 3));

    assert.deepEqual([...seen].sort(), [1, 2, 3]);
  });

  test("a single-value range returns that value", () => {
    const random = createRandom("single");
    assert.equal(random.int(7, 7), 7);
  });

  test("a reversed range is swapped rather than throwing", () => {
    const random = createRandom("reversed");
    const value = random.int(10, 2);

    assert.ok(value >= 2 && value <= 10);
  });

  test("handles negative ranges", () => {
    const random = createRandom("negative");

    for (let i = 0; i < 200; i += 1) {
      const value = random.int(-5, -1);
      assert.ok(value >= -5 && value <= -1, `out of range: ${value}`);
    }
  });
});

describe("createRandom — pick", () => {
  test("only ever returns members of the array", () => {
    const random = createRandom("pick");
    const items = ["s3", "ec2", "iam"] as const;

    for (let i = 0; i < 200; i += 1) {
      assert.ok(items.includes(random.pick(items)));
    }
  });

  test("can return every member", () => {
    const random = createRandom("pick-coverage");
    const items = ["a", "b", "c", "d"] as const;
    const seen = new Set(
      Array.from({ length: 400 }, () => random.pick(items)),
    );

    assert.equal(seen.size, 4);
  });

  test("throws on an empty array rather than returning undefined", () => {
    const random = createRandom("pick-empty");

    assert.throws(() => random.pick([]), RangeError);
  });

  test("a single-element array always returns that element", () => {
    const random = createRandom("pick-one");
    assert.equal(random.pick(["only"]), "only");
  });
});

describe("createRandom — bool", () => {
  test("clamps probabilities at both ends", () => {
    const random = createRandom("bool-clamp");

    for (let i = 0; i < 100; i += 1) {
      assert.equal(random.bool(0), false);
      assert.equal(random.bool(1), true);
      // Out-of-range values must clamp, not wrap or throw.
      assert.equal(random.bool(-5), false);
      assert.equal(random.bool(5), true);
    }
  });

  test("roughly honours the requested probability", () => {
    const random = createRandom("bool-rate");
    let trueCount = 0;

    for (let i = 0; i < 10_000; i += 1) {
      if (random.bool(0.25)) trueCount += 1;
    }

    // Wide tolerance on purpose — see the file header.
    assert.ok(
      trueCount > 2200 && trueCount < 2800,
      `expected ~2500 true results, got ${trueCount}`,
    );
  });
});

describe("createRandom — normal", () => {
  test("produces finite numbers only", () => {
    // Guards the `Math.log(0)` case: without the `1 - next()` correction this
    // eventually yields Infinity, and Infinity in an event timestamp would
    // surface as an unreadable fixture much later.
    const random = createRandom("normal-finite");

    for (let i = 0; i < 20_000; i += 1) {
      assert.ok(Number.isFinite(random.normal(100, 25)));
    }
  });

  test("centres on the mean with roughly the requested spread", () => {
    const random = createRandom("normal-shape");
    const samples = Array.from({ length: 20_000 }, () =>
      random.normal(50, 10),
    );

    const mean = samples.reduce((sum, v) => sum + v, 0) / samples.length;
    const variance =
      samples.reduce((sum, v) => sum + (v - mean) ** 2, 0) / samples.length;
    const stdDev = Math.sqrt(variance);

    assert.ok(Math.abs(mean - 50) < 1, `mean drifted: ${mean}`);
    assert.ok(Math.abs(stdDev - 10) < 1, `spread wrong: ${stdDev}`);
  });

  test("a negative standard deviation is treated as its absolute value", () => {
    const random = createRandom("normal-negative");
    const samples = Array.from({ length: 5000 }, () => random.normal(0, -5));
    const mean = samples.reduce((sum, v) => sum + v, 0) / samples.length;

    assert.ok(Math.abs(mean) < 1, `mean drifted: ${mean}`);
  });

  test("a zero standard deviation returns the mean exactly", () => {
    const random = createRandom("normal-zero");

    for (let i = 0; i < 100; i += 1) {
      assert.equal(random.normal(42, 0), 42);
    }
  });
});

describe("createRandom — shuffle", () => {
  test("does not modify the input array", () => {
    const random = createRandom("shuffle-pure");
    const input = [1, 2, 3, 4, 5];
    const original = [...input];

    random.shuffle(input);

    assert.deepEqual(input, original);
  });

  test("preserves every element exactly once", () => {
    const random = createRandom("shuffle-perm");
    const input = [...Array(50).keys()];

    const shuffled = random.shuffle(input);

    assert.equal(shuffled.length, input.length);
    assert.deepEqual([...shuffled].sort((a, b) => a - b), input);
  });

  test("actually changes the order", () => {
    const random = createRandom("shuffle-order");
    const input = [...Array(30).keys()];

    // A correct shuffle of 30 elements returning the identity permutation has
    // probability 1/30!, so this is a safe assertion rather than a flaky one.
    assert.notDeepEqual(random.shuffle(input), input);
  });

  test("handles empty and single-element arrays", () => {
    const random = createRandom("shuffle-edge");

    assert.deepEqual(random.shuffle([]), []);
    assert.deepEqual(random.shuffle(["x"]), ["x"]);
  });
});
