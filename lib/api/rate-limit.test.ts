/**
 * CloudSentinel — tests for the login rate limiter.
 *
 * Run with `npm test`. Pure in-memory logic, no network and no database.
 *
 * Two properties matter here and neither is visible in ordinary use, which is
 * exactly why they are worth asserting: the limiter counts *every* attempt
 * rather than only the failures, and keys are independent of one another. Both
 * are the kind of thing a well-meaning refactor breaks silently — the endpoint
 * keeps working, it just stops protecting anything.
 */

import assert from "node:assert/strict";
import { beforeEach, describe, test } from "node:test";

import {
  checkRateLimit,
  clientKey,
  resetAllRateLimitsForTests,
  resetRateLimit,
} from "./rate-limit.ts";

/** Matches MAX_ATTEMPTS in the module under test. */
const LIMIT = 10;

beforeEach(() => {
  // The limiter's state is module-level, so tests would otherwise inherit each
  // other's counts and fail in an order-dependent way.
  resetAllRateLimitsForTests();
});

describe("checkRateLimit", () => {
  test("allows exactly the budget, then blocks", () => {
    for (let attempt = 1; attempt <= LIMIT; attempt += 1) {
      assert.equal(
        checkRateLimit("1.2.3.4").allowed,
        true,
        `attempt ${attempt} should be allowed`,
      );
    }

    assert.equal(checkRateLimit("1.2.3.4").allowed, false);
    // And it stays blocked rather than allowing one through per call.
    assert.equal(checkRateLimit("1.2.3.4").allowed, false);
  });

  test("counts down remaining accurately", () => {
    assert.equal(checkRateLimit("k").remaining, LIMIT - 1);
    assert.equal(checkRateLimit("k").remaining, LIMIT - 2);
  });

  test("never reports negative remaining", () => {
    for (let i = 0; i < LIMIT + 5; i += 1) checkRateLimit("k");
    assert.equal(checkRateLimit("k").remaining, 0);
  });

  test("keeps keys independent", () => {
    // One client exhausting its budget must not lock everybody else out. A
    // limiter that shared a counter across all callers would be a
    // denial-of-service vector rather than a defence against one.
    for (let i = 0; i < LIMIT + 1; i += 1) checkRateLimit("attacker");

    assert.equal(checkRateLimit("attacker").allowed, false);
    assert.equal(checkRateLimit("someone-else").allowed, true);
  });

  test("reports a positive retry-after when blocked", () => {
    for (let i = 0; i < LIMIT + 1; i += 1) checkRateLimit("k");

    const result = checkRateLimit("k");
    assert.equal(result.allowed, false);
    // Sent to the client as `Retry-After`. A zero or negative value would tell
    // a well-behaved client to retry immediately, which defeats the purpose.
    assert.ok(result.retryAfterSeconds > 0);
    assert.ok(result.retryAfterSeconds <= 15 * 60);
  });
});

describe("resetRateLimit", () => {
  test("clears one key's budget", () => {
    for (let i = 0; i < LIMIT; i += 1) checkRateLimit("k");
    assert.equal(checkRateLimit("k").allowed, false);

    // Called after a successful login: somebody who mistyped their password a
    // few times should not stay throttled once they get it right.
    resetRateLimit("k");
    assert.equal(checkRateLimit("k").allowed, true);
  });

  test("does not clear other keys", () => {
    for (let i = 0; i < LIMIT + 1; i += 1) checkRateLimit("a");
    resetRateLimit("b");
    assert.equal(checkRateLimit("a").allowed, false);
  });
});

describe("clientKey", () => {
  test("uses the first x-forwarded-for entry", () => {
    // The header is a comma-separated chain: the original client first, then
    // each intermediary. Taking the last would key on the proxy, giving every
    // client behind it one shared budget.
    const request = new Request("http://localhost/", {
      headers: { "x-forwarded-for": "203.0.113.7, 10.0.0.1, 10.0.0.2" },
    });
    assert.equal(clientKey(request), "203.0.113.7");
  });

  test("falls back to x-real-ip", () => {
    const request = new Request("http://localhost/", {
      headers: { "x-real-ip": "203.0.113.9" },
    });
    assert.equal(clientKey(request), "203.0.113.9");
  });

  test("falls back to a shared bucket when no address is available", () => {
    // Deliberate: unidentifiable clients share one budget, so the failure mode
    // is throttling too much rather than not at all.
    assert.equal(clientKey(new Request("http://localhost/")), "unknown");
  });

  test("ignores an empty header rather than keying on an empty string", () => {
    const request = new Request("http://localhost/", {
      headers: { "x-forwarded-for": "  ," },
    });
    assert.equal(clientKey(request), "unknown");
  });
});
