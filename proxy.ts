/**
 * CloudSentinel — Content Security Policy.
 *
 * (Named `proxy.ts` because Next 16 renamed this file convention from
 * `middleware.ts`. It is the same hook at the same point in the request path;
 * only the filename and the exported function's name changed. The old spelling
 * still works but logs a deprecation warning on every build, and a security
 * project should not ship one.)
 *
 * Issues a fresh cryptographic nonce for every HTML response and emits the
 * Content-Security-Policy header that permits exactly the scripts carrying it.
 *
 * Where it sits in the architecture: in front of every page and API route, but
 * doing only one job. The other security headers — the ones with no per-request
 * component — are set in next.config.ts instead, because a static header does
 * not need code to run on every request to produce it.
 *
 *   request --> [ this file: mint nonce, set CSP ] --> app/ route or page
 *
 * ===========================================================================
 * This file does NOT authenticate anything, and that is deliberate
 * ===========================================================================
 *
 * Phase 5 established that session checks live in the route handlers, via
 * `requireUser()` / `requireAdmin()` in lib/api/http.ts, rather than in
 * middleware. The reason still holds: middleware runs on the Edge runtime,
 * which has neither `node:crypto` nor a database connection, so a check here
 * could not verify an HS256 signature with the project's own implementation and
 * could not compare `token_version` against the database to honour a
 * revocation. It would have to trust the token's own claims — which is precisely
 * the mistake lib/auth/jwt.ts is written to avoid.
 *
 * Adding this file does not reopen that question. Minting a nonce needs only
 * `crypto.getRandomValues`, which the Edge runtime provides, and reads nothing
 * about who is making the request. An attacker gains nothing from a CSP nonce
 * and there is no decision here to get wrong.
 *
 * ===========================================================================
 * Why a nonce rather than a static policy
 * ===========================================================================
 *
 * The simple version of a CSP for a React application is
 * `script-src 'self' 'unsafe-inline'`, because Next inlines a bootstrap script
 * and streams server-rendered data as inline `<script>` tags during hydration.
 * But `'unsafe-inline'` permits *every* inline script, which is the exact thing
 * an injected `<script>` is, so a policy containing it provides no protection
 * against cross-site scripting at all — it looks like a control and is not one.
 *
 * A nonce solves it properly. The value is unpredictable and changes on every
 * response, so Next's own scripts can be marked with it while an injected one —
 * written by an attacker who cannot know this request's nonce — is refused by
 * the browser. Next reads the nonce out of this header and stamps it onto the
 * scripts it generates.
 */

import { NextResponse, type NextRequest } from "next/server";

/**
 * Bytes of randomness in each nonce.
 *
 * 16 bytes / 128 bits. A CSP nonce only has to be unguessable for the lifetime
 * of one response, but the cost of generating more is nil and the cost of
 * guessing one correctly is a bypassed script policy.
 */
const NONCE_BYTES = 16;

/**
 * Mints a single-use nonce.
 *
 * Uses Web Crypto rather than `node:crypto`, which does not exist on the Edge
 * runtime this file executes in. `Math.random()` would be catastrophically wrong
 * here — it is a predictable pseudo-random generator, so an attacker able to
 * observe a few nonces could compute the next one and sign their injected
 * script with it.
 */
function mintNonce(): string {
  const bytes = new Uint8Array(NONCE_BYTES);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

/**
 * Builds the policy for one response.
 *
 * Each directive below is a decision, so each is annotated. The general shape is
 * "deny everything, then permit what this application actually does" — the same
 * posture as k8s/40-networkpolicy.yaml, applied to the browser.
 */
function contentSecurityPolicy(nonce: string): string {
  return [
    // The fallback for every fetch directive not named explicitly. Starting
    // from `'self'` means a directive nobody thought to list defaults to
    // same-origin rather than to open.
    `default-src 'self'`,

    // Scripts: only same-origin files and inline scripts carrying this
    // response's nonce.
    //
    // `'strict-dynamic'` is what makes this workable with a bundler. It says
    // that a script already trusted — one with the nonce — may load further
    // scripts, which is exactly how Next's bootstrap pulls in its chunks.
    // Without it every chunk URL would have to be enumerated here, which is
    // impossible when their hashed names change on every build.
    //
    // A useful side effect: `'strict-dynamic'` makes conforming browsers ignore
    // `'self'` and any host allowlist in this directive, so the policy cannot be
    // weakened later by someone adding a convenient CDN to the list. The `'self'`
    // that remains is a fallback for older browsers that do not implement
    // `'strict-dynamic'`.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,

    // Styles: same-origin, plus inline.
    //
    // `'unsafe-inline'` here is a deliberate, narrower compromise than it would
    // be for scripts, and it is worth being honest about. Next injects inline
    // `<style>` blocks for critical CSS and for the font declarations that
    // `next/font` generates, and it does not nonce them. The exposure is CSS
    // injection — an attacker who already has an injection point could restyle
    // the page or, with effort, use selectors to exfiltrate the presence of
    // some attribute values. That is real but is a long way short of script
    // execution, and the alternative is a policy that breaks the dashboard's
    // rendering entirely.
    `style-src 'self' 'unsafe-inline'`,

    // Images: same-origin plus `data:` URIs. Nothing here loads a remote image,
    // and a security dashboard fetching images from third-party hosts would be
    // leaking which pages are being viewed to whoever serves them.
    `img-src 'self' data:`,

    // Fonts are self-hosted. `next/font` downloads the Geist faces at build
    // time and serves them from this origin precisely so no request is made to
    // Google's servers at page load — so no external font host is needed here.
    `font-src 'self'`,

    // XHR, fetch and WebSocket targets. The dashboard talks only to its own API
    // routes, so this closes the most direct exfiltration path an injected
    // script would reach for.
    `connect-src 'self'`,

    // No plugins, ever. `<object>` and `<embed>` are a legacy execution vector
    // with no modern use.
    `object-src 'none'`,

    // Refuses a `<base>` tag. Without this, an injected `<base href>` can
    // silently repoint every relative URL on the page — including script
    // sources — at an attacker's host.
    `base-uri 'none'`,

    // Forms may only submit to this origin. This is what stops an injected form
    // from posting the contents of the login form somewhere else.
    `form-action 'self'`,

    // Nothing may frame this application. Together with X-Frame-Options in
    // next.config.ts (which covers browsers predating this directive), it is the
    // clickjacking defence: without it, a hostile page could load the dashboard
    // in an invisible frame and trick a signed-in admin into clicking the
    // suppress control.
    `frame-ancestors 'none'`,

    // This application frames nothing.
    `frame-src 'none'`,

    // Note what is *not* here: `upgrade-insecure-requests`. It would be correct
    // for a production deployment behind TLS, and wrong for this one — the
    // Kubernetes NodePort serves plain HTTP on localhost, and upgrading those
    // requests would break the dashboard against a server that has no HTTPS
    // listener. It belongs with the Ingress that terminates TLS, which is
    // recorded as a follow-up rather than pretended at here.
  ].join("; ");
}

export function proxy(request: NextRequest): NextResponse {
  const nonce = mintNonce();
  const policy = contentSecurityPolicy(nonce);

  // The nonce is passed forward on the *request* headers as well as being set
  // on the response. That is not redundancy: Next reads the policy back off the
  // incoming request to discover the nonce, and stamps it onto the script tags
  // it renders. Set it only on the response and Next's own scripts go out
  // without a nonce — and are then refused by the policy, leaving a blank page
  // that is genuinely puzzling to debug.
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("content-security-policy", policy);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("content-security-policy", policy);

  return response;
}

export const config = {
  /**
   * Which requests this runs for.
   *
   * Everything except Next's build output, the favicon, and the font files.
   * Those are static assets that contain no HTML, so there is no script for a
   * policy to constrain — and minting a nonce for each of them would mean
   * running this code dozens of times per page load for no benefit.
   *
   * API routes are deliberately *included*. They return JSON rather than HTML,
   * so the policy has little to act on, but `frame-ancestors` and `base-uri`
   * cost nothing there and the alternative is an exception that has to stay
   * correct as routes are added.
   */
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:woff|woff2|ttf|otf)$).*)",
  ],
};
