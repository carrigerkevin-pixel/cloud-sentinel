/**
 * CloudSentinel — seeded pseudo-random number generator.
 *
 * A small, deterministic PRNG: the same seed always produces the same sequence
 * of numbers, on any machine, in any Node version, forever.
 *
 * Where it sits in the architecture: a leaf utility with no dependencies.
 * lib/logs/generator.ts uses it to synthesize CloudTrail-style activity logs
 * for the ML anomaly layer. Nothing else depends on it.
 *
 *   [ this file ] --> lib/logs/generator.ts --> fixtures/cloudtrail.json
 *                                                       |
 *                                                       v
 *                                              ml/ (feature extraction,
 *                                                anomaly detection)
 *
 * Why determinism is a hard requirement rather than a nicety:
 *
 *   - The generated log is committed as a fixture. If generation were random,
 *     regenerating it would produce a completely different diff every time and
 *     the file would be unreviewable.
 *   - The ML layer is evaluated against injected, labelled attacks. "The
 *     detector caught 5 of 5 scenarios" is only a meaningful test if the 5
 *     scenarios are the same 5 on every run. With `Math.random()` the suite
 *     would pass or fail depending on the day, which is worse than having no
 *     test at all — a flaky test trains you to ignore it.
 *   - Anomaly detection is judged on thresholds. Tuning a threshold against
 *     data that changes underneath you is not tuning, it is guessing.
 *
 * SECURITY: this is `Math.random()`-grade randomness and must never be used for
 * anything security-sensitive — not tokens, not salts, not session ids, not
 * passwords. It is fully predictable *by design*: given the seed, every number
 * it will ever produce can be computed. Real security randomness in this
 * project comes from `node:crypto` (see lib/auth/password.ts and
 * lib/auth/jwt.ts), and the two must not be confused. The only thing this
 * generator is allowed to produce is synthetic test data.
 */

// ---------------------------------------------------------------------------
// Seeding
// ---------------------------------------------------------------------------

/**
 * Hashes a string seed down to a 32-bit integer, using FNV-1a.
 *
 * The PRNG below needs a 32-bit integer to start from, but a human-chosen seed
 * like `"cloudsentinel-2026"` is far more legible in a config file or a test
 * than a magic number such as `2463534242`. This bridges the two.
 *
 * FNV-1a is chosen because it is about six lines long and avalanches well
 * enough that two similar seeds (`"run-1"` and `"run-2"`) produce unrelated
 * streams. It is *not* a cryptographic hash and does not need to be — see the
 * SECURITY note in the file header.
 *
 * @param seed - any string, including the empty string.
 * @returns an unsigned 32-bit integer.
 */
function hashSeed(seed: string): number {
  // FNV-1a 32-bit offset basis.
  let hash = 0x811c9dc5;

  for (let index = 0; index < seed.length; index += 1) {
    hash ^= seed.charCodeAt(index);
    // The FNV prime is 16777619. `Math.imul` performs the multiply with 32-bit
    // overflow semantics; a plain `*` would promote to a float above 2^53 and
    // silently lose the low bits that carry all the entropy.
    hash = Math.imul(hash, 16777619);
  }

  // `>>> 0` reinterprets the sign bit, yielding an unsigned value.
  return hash >>> 0;
}

// ---------------------------------------------------------------------------
// The generator
// ---------------------------------------------------------------------------

/**
 * A deterministic source of random-looking values.
 *
 * Every method advances the same internal 32-bit state, so the *order* of calls
 * matters: inserting one extra `next()` shifts every subsequent value. That is
 * worth knowing when editing lib/logs/generator.ts, because it means adding a
 * new random decision in the middle of the generator changes the whole log
 * downstream of it, not just the part being edited.
 */
export interface Random {
  /** A float in `[0, 1)` — the primitive every other method is built on. */
  next(): number;

  /**
   * An integer in `[min, max]`, both ends inclusive.
   *
   * Inclusive at both ends because almost every use here is a natural range
   * ("an hour from 9 to 17", "between 1 and 4 retries") where excluding the top
   * is a persistent source of off-by-one bugs.
   *
   * @param min - lowest value that may be returned.
   * @param max - highest value that may be returned. If `max < min` the two are
   *   swapped rather than throwing, so a caller computing a range from data
   *   cannot crash the generator on an empty edge case.
   */
  int(min: number, max: number): number;

  /**
   * Picks one element of an array, uniformly.
   *
   * @param items - must not be empty.
   * @throws {RangeError} if `items` is empty. This throws rather than returning
   *   `undefined` because every call site here passes a non-empty literal, so
   *   an empty array means the caller built the list wrongly — and a silent
   *   `undefined` would travel into a generated log field and surface much
   *   later as a confusing parse error in the Python layer.
   */
  pick<T>(items: readonly T[]): T;

  /**
   * A weighted coin flip.
   *
   * @param probability - chance of `true`, from 0 to 1. Values outside that
   *   range are clamped, so `bool(1)` is always true and `bool(0)` never is.
   */
  bool(probability: number): boolean;

  /**
   * A sample from a normal (Gaussian) distribution.
   *
   * Used for quantities that cluster around a typical value with occasional
   * outliers — how many API calls a principal makes in an hour, how many
   * minutes past the hour an event lands. A uniform distribution would produce
   * activity that is suspiciously flat, and flat data makes an anomaly detector
   * look better than it is: if normal behaviour has no natural variance, then
   * *any* variance reads as an anomaly and the model has no real work to do.
   *
   * @param mean - centre of the distribution.
   * @param stdDev - standard deviation. Negative values are treated as their
   *   absolute value.
   * @returns an unbounded float — it can be negative even when `mean` is
   *   positive. Callers that need a floor must clamp it themselves.
   */
  normal(mean: number, stdDev: number): number;

  /**
   * Returns a new array with the elements in random order.
   *
   * Does not modify the input. Uses Fisher-Yates, which is the only shuffle
   * that is actually uniform — the common `sort(() => random() - 0.5)` trick is
   * biased, and how biased depends on the engine's sort implementation.
   *
   * @param items - source array; left untouched.
   */
  shuffle<T>(items: readonly T[]): T[];
}

/**
 * Creates a {@link Random} from a seed.
 *
 * The algorithm is mulberry32: a 32-bit state, one addition, two multiplies and
 * a handful of shifts per value. It is not the highest-quality PRNG available,
 * but it passes the statistical tests that matter for generating plausible
 * traffic, it needs no dependency, and — the point — it is short enough to read
 * and confirm that nothing hidden is going on.
 *
 * @param seed - a string (hashed by {@link hashSeed}) or a number used
 *   directly. Two callers passing the same seed get identical sequences.
 * @returns an independent generator. Separate calls do not share state, so one
 *   part of the log generator cannot perturb another by drawing extra numbers.
 *
 * @example
 * const random = createRandom("cloudsentinel");
 * random.int(1, 6); // same value on every machine, every run
 */
export function createRandom(seed: string | number): Random {
  let state = (typeof seed === "string" ? hashSeed(seed) : seed >>> 0) | 0;

  const next = (): number => {
    // mulberry32. The constants are the published ones; changing any of them
    // changes every fixture in the repository, so they are effectively frozen.
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };

  // Box-Muller produces normal samples in pairs. Caching the second one halves
  // the number of `next()` calls, but note the consequence for determinism: the
  // sequence consumed by `normal()` depends on whether a spare is waiting. That
  // is fine because the cache lives inside this one generator instance and is
  // therefore itself deterministic.
  let spareNormal: number | null = null;

  return {
    next,

    int(min: number, max: number): number {
      const low = Math.min(min, max);
      const high = Math.max(min, max);
      return low + Math.floor(next() * (high - low + 1));
    },

    pick<T>(items: readonly T[]): T {
      if (items.length === 0) {
        throw new RangeError(
          "createRandom().pick: cannot pick from an empty array",
        );
      }
      // Non-null assertion is safe: the index is in `[0, length - 1]` and the
      // empty case was rejected above.
      return items[Math.floor(next() * items.length)]!;
    },

    bool(probability: number): boolean {
      if (probability <= 0) return false;
      if (probability >= 1) return true;
      return next() < probability;
    },

    normal(mean: number, stdDev: number): number {
      const deviation = Math.abs(stdDev);

      if (spareNormal !== null) {
        const value = spareNormal;
        spareNormal = null;
        return mean + deviation * value;
      }

      // Box-Muller transform. `1 - next()` avoids `Math.log(0)`, which is
      // -Infinity and would produce NaN downstream — rare, but with tens of
      // thousands of generated events "rare" happens.
      const magnitude = Math.sqrt(-2 * Math.log(1 - next()));
      const angle = 2 * Math.PI * next();

      spareNormal = magnitude * Math.sin(angle);
      return mean + deviation * magnitude * Math.cos(angle);
    },

    shuffle<T>(items: readonly T[]): T[] {
      const copy = [...items];
      // Fisher-Yates, walking backwards and swapping each element with a
      // uniformly chosen element at or before it.
      for (let index = copy.length - 1; index > 0; index -= 1) {
        const target = Math.floor(next() * (index + 1));
        [copy[index], copy[target]] = [copy[target]!, copy[index]!];
      }
      return copy;
    },
  };
}
