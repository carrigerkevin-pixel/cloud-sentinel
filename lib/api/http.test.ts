/**
 * CloudSentinel — tests for the cross-site request forgery guard.
 *
 * Run with `npm test`. Needs no database and no server: `checkSameOrigin` is a
 * pure function of two request headers, which is why it was written as one.
 *
 * Where this sits in the architecture: it covers the second layer of CSRF
 * defence on the three state-changing routes (`/api/auth/login`,
 * `/api/auth/logout`, `/api/findings/[id]/triage`). The first layer is the
 * `SameSite=strict` cookie in lib/auth/session.ts, which is enforced by the
 * browser; this one is enforced by the server, and the point of having both is
 * that the project does not get to choose the client.
 *
 * The tests are weighted toward the ways an origin check is commonly written
 * wrong, because every one of those bugs produces a check that *looks* present
 * and accepts an attacker's request anyway:
 *
 *   - accepting a missing header, which leaves an opt-out consisting of not
 *     sending one;
 *   - comparing with `startsWith` or `includes`, which accepts
 *     `evil-example.com` and `example.com.evil.test`;
 *   - comparing the full origin string against a host, so that a port or a
 *     scheme difference silently never matches.
 */

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { checkSameOrigin } from "./http.ts";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Builds a request carrying the given headers.
 *
 * The URL is irrelevant to the code under test — it reads `Host` and `Origin`
 * from the headers, never from the URL — but `Request` requires one.
 */
function request(headers: Record<string, string>): Request {
  return new Request("http://cloudsentinel.test/api/findings/x/triage", {
    method: "POST",
    headers,
  });
}

/** Asserts the request was allowed through. */
function assertAllowed(result: Response | null): void {
  assert.equal(result, null, "expected the request to be allowed");
}

/** Asserts the request was refused with a 403. */
async function assertRefused(result: Response | null): Promise<void> {
  assert.ok(result, "expected the request to be refused");
  assert.equal(result.status, 403);

  const body = (await result.json()) as { error: { code: string; message: string } };
  assert.equal(body.error.code, "forbidden");
  return;
}

// ---------------------------------------------------------------------------
// Same origin
// ---------------------------------------------------------------------------

describe("checkSameOrigin — requests that must be allowed", () => {
  test("accepts an origin matching the host", () => {
    assertAllowed(
      checkSameOrigin(
        request({
          origin: "http://cloudsentinel.test",
          host: "cloudsentinel.test",
        }),
      ),
    );
  });

  test("accepts a matching host that carries a port", () => {
    // The Kubernetes NodePort deployment is reached at localhost:30080, and the
    // dev server at localhost:3000. Both must work with no configuration, which
    // is why the expected host comes from the request rather than from an
    // environment variable someone has to keep in step.
    assertAllowed(
      checkSameOrigin(
        request({
          origin: "http://localhost:30080",
          host: "localhost:30080",
        }),
      ),
    );
  });

  test("ignores the scheme when the host matches", () => {
    // `Host` carries no scheme, so only the host and port are comparable. This
    // is a deliberate limitation rather than an oversight: a same-host request
    // arriving over the wrong scheme is a transport problem for
    // Strict-Transport-Security to solve, not something this check can see.
    assertAllowed(
      checkSameOrigin(
        request({
          origin: "https://cloudsentinel.test",
          host: "cloudsentinel.test",
        }),
      ),
    );
  });
});

// ---------------------------------------------------------------------------
// Cross origin — the cases that matter
// ---------------------------------------------------------------------------

describe("checkSameOrigin — requests that must be refused", () => {
  test("refuses an outright different origin", async () => {
    await assertRefused(
      checkSameOrigin(
        request({
          origin: "https://attacker.test",
          host: "cloudsentinel.test",
        }),
      ),
    );
  });

  test("refuses a suffix that would pass a naive substring check", async () => {
    // `cloudsentinel.test.attacker.test` contains the real host as a prefix, so
    // an implementation using `startsWith` accepts it. It is a domain the
    // attacker controls.
    await assertRefused(
      checkSameOrigin(
        request({
          origin: "https://cloudsentinel.test.attacker.test",
          host: "cloudsentinel.test",
        }),
      ),
    );
  });

  test("refuses a prefix that would pass a naive substring check", async () => {
    // The mirror image: `evil-cloudsentinel.test` *ends with* the real host, so
    // an implementation using `endsWith` or `includes` accepts it.
    await assertRefused(
      checkSameOrigin(
        request({
          origin: "https://evil-cloudsentinel.test",
          host: "cloudsentinel.test",
        }),
      ),
    );
  });

  test("refuses a different port on the same hostname", async () => {
    // Ports are part of an origin. Another service on the same machine is a
    // different origin, and on a shared development box it may well be one
    // somebody else is running.
    await assertRefused(
      checkSameOrigin(
        request({ origin: "http://localhost:9999", host: "localhost:30080" }),
      ),
    );
  });

  test("refuses a subdomain", async () => {
    // This is the gap that justifies the whole function. `SameSite=strict` uses
    // the registrable domain, so a page on a sibling subdomain is *same-site*
    // and its requests carry the session cookie. Only an origin comparison
    // distinguishes them.
    await assertRefused(
      checkSameOrigin(
        request({
          origin: "https://staging.cloudsentinel.test",
          host: "cloudsentinel.test",
        }),
      ),
    );
  });

  test("refuses the literal string \"null\"", async () => {
    // Browsers send `Origin: null` from a sandboxed iframe, a `data:` URL, and
    // some redirect chains — all contexts an attacker can arrange, and none
    // that the dashboard is ever served from.
    await assertRefused(
      checkSameOrigin(
        request({ origin: "null", host: "cloudsentinel.test" }),
      ),
    );
  });
});

// ---------------------------------------------------------------------------
// Missing and malformed headers
// ---------------------------------------------------------------------------

describe("checkSameOrigin — absent or unparseable headers", () => {
  test("refuses a request with no Origin header", async () => {
    // The decision that matters most in this file. Browsers always send Origin
    // on the requests this guards, so absence means the caller is not one.
    // Allowing it would reduce the entire control to an opt-out that consists
    // of omitting a header.
    await assertRefused(checkSameOrigin(request({ host: "cloudsentinel.test" })));
  });

  test("refuses a request with no Host header", async () => {
    await assertRefused(
      checkSameOrigin(request({ origin: "http://cloudsentinel.test" })),
    );
  });

  test("refuses a malformed Origin rather than throwing", async () => {
    // `new URL()` throws on input like this. An unhandled throw inside a route
    // becomes a 500, which both implies the server is broken and invites a
    // retry of something that can never succeed.
    for (const origin of ["not a url", "://missing-scheme", "http://"]) {
      await assertRefused(
        checkSameOrigin(request({ origin, host: "cloudsentinel.test" })),
      );
    }
  });

  test("never reflects the rejected origin back to the caller", async () => {
    // Echoing an attacker-supplied value into a response body is a habit worth
    // not having, even where it is currently harmless.
    const result = checkSameOrigin(
      request({ origin: "https://attacker.test", host: "cloudsentinel.test" }),
    );
    assert.ok(result);
    const body = await result.text();
    assert.ok(
      !body.includes("attacker.test"),
      `the rejected origin was reflected in the response: ${body}`,
    );
  });
});
