/**
 * CloudSentinel — in-process rate limiting for the login endpoint.
 *
 * A fixed-window counter keyed by client address, used to slow down password
 * guessing.
 *
 * Where it sits in the architecture:
 *
 *   POST /api/auth/login --> [ this file ] --> lib/db/users.ts authenticate()
 *
 * ## Why this exists
 *
 * scrypt makes an *offline* attack expensive: someone who has stolen the
 * `users` table cannot cheaply grind through a password list. It does nothing
 * about an *online* attack, where the attacker simply asks the login endpoint
 * over and over. Ten requests per second against a dashboard with one
 * `summer2027` password will find it, and the only trace is a pile of 401s
 * nobody reads.
 *
 * Worse, scrypt's cost works against the defender here: every attempt burns
 * ~100 ms of CPU and 16 MB on the server, so an unthrottled login endpoint is
 * also a denial-of-service amplifier — a handful of concurrent attackers can
 * saturate the machine with unauthenticated requests.
 *
 * ## What this deliberately is not
 *
 * This is an in-memory counter in one Node process. Three honest limitations:
 *
 *   1. **It resets when the process restarts.** An attacker who can trigger a
 *      restart clears their record.
 *   2. **It does not survive horizontal scaling.** Two instances behind a load
 *      balancer each allow the full quota, so the effective limit doubles.
 *   3. **It trusts a client address that can be spoofed** when the app is not
 *      behind a proxy that sets `x-forwarded-for` itself — see
 *      {@link clientKey}.
 *
 * Those are acceptable for a locally-hosted project, and unacceptable for a
 * real deployment, which is why they are written down rather than glossed over.
 * The production answer is a shared store (Redis) or a limit enforced at the
 * reverse proxy, and this module's interface is deliberately narrow enough to
 * swap for one.
 */

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** Attempts permitted per window, per key. */
const MAX_ATTEMPTS = 10;

/** Window length in milliseconds. */
const WINDOW_MS = 15 * 60 * 1000;

/**
 * Hard ceiling on tracked keys.
 *
 * Without one, the map is itself a memory-exhaustion vector: an attacker
 * rotating source addresses would add an entry per request forever. A rate
 * limiter that can be turned into a memory leak has made the problem worse
 * rather than better.
 */
const MAX_TRACKED_KEYS = 10_000;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

interface Window {
  count: number;
  /** Epoch milliseconds at which this window expires. */
  resetAt: number;
}

const windows = new Map<string, Window>();

/** Drops expired entries, and everything if the map has grown past its ceiling. */
function evictStale(now: number): void {
  for (const [key, window] of windows) {
    if (window.resetAt <= now) windows.delete(key);
  }

  // Still oversized after dropping the expired ones: clear it entirely. This
  // briefly forgives everyone, which is the lesser evil — the alternative is
  // unbounded growth, and choosing which live entries to discard fairly is not
  // worth the complexity at this scale.
  if (windows.size > MAX_TRACKED_KEYS) windows.clear();
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

/** The outcome of a rate-limit check. */
export interface RateLimitResult {
  allowed: boolean;
  /** Attempts left in the current window. */
  remaining: number;
  /** Seconds until the window resets. Sent as `Retry-After` when blocked. */
  retryAfterSeconds: number;
}

/**
 * Records an attempt and reports whether it may proceed.
 *
 * Counts every attempt rather than only the failures. Counting failures alone
 * would let an attacker interleave one known-good login between guesses to keep
 * their budget topped up.
 *
 * @param key - identifies the client. See {@link clientKey}.
 * @returns whether to proceed, and what to tell the client if not.
 */
export function checkRateLimit(key: string): RateLimitResult {
  const now = Date.now();
  evictStale(now);

  const existing = windows.get(key);

  if (!existing || existing.resetAt <= now) {
    windows.set(key, { count: 1, resetAt: now + WINDOW_MS });
    return {
      allowed: true,
      remaining: MAX_ATTEMPTS - 1,
      retryAfterSeconds: Math.ceil(WINDOW_MS / 1000),
    };
  }

  existing.count += 1;

  const retryAfterSeconds = Math.max(
    1,
    Math.ceil((existing.resetAt - now) / 1000),
  );

  return {
    allowed: existing.count <= MAX_ATTEMPTS,
    remaining: Math.max(0, MAX_ATTEMPTS - existing.count),
    retryAfterSeconds,
  };
}

/**
 * Clears a key's window.
 *
 * Called after a successful login, so that someone who mistyped their password
 * a few times is not still throttled once they get it right. The budget exists
 * to slow guessing, not to punish typing.
 */
export function resetRateLimit(key: string): void {
  windows.delete(key);
}

/** Empties all state. Exists for tests, which must not leak counts into each other. */
export function resetAllRateLimitsForTests(): void {
  windows.clear();
}

/**
 * Derives a rate-limit key from a request.
 *
 * SECURITY: `x-forwarded-for` is a client-supplied header. Anything reading it
 * is trusting the caller unless a reverse proxy in front of the application
 * overwrites it — and if none does, an attacker sets a fresh value per request
 * and never hits a limit. The header is used here because the intended
 * deployment is behind a proxy, and the fallback below keeps the limiter useful
 * when it is absent.
 *
 * `x-forwarded-for` is a comma-separated chain; the *first* entry is the
 * original client and the rest are intermediaries.
 *
 * @param request - the incoming request.
 * @returns an address, or the literal `"unknown"` when none can be determined.
 *   Sharing one bucket among unidentifiable clients is deliberate: the failure
 *   mode is throttling too much, never too little.
 */
export function clientKey(request: Request): string {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) {
    const first = forwarded.split(",")[0]?.trim();
    if (first) return first;
  }

  return request.headers.get("x-real-ip")?.trim() || "unknown";
}
