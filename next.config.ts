/**
 * CloudSentinel — Next.js build configuration.
 *
 * Where it fits in the architecture: this governs how the dashboard and its API
 * routes (app/) are compiled. It affects nothing in the collector, the rule
 * engine, or the ML layer, all of which run as standalone CLIs.
 */

import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /**
   * Emit a self-contained server bundle at `.next/standalone`.
   *
   * This exists for the container image. Without it, a runtime image has to
   * carry the whole `node_modules` tree — 500MB here, most of it the AWS SDK,
   * TypeScript, ESLint and the React toolchain, none of which the running
   * dashboard calls. `standalone` instead traces which files the server
   * actually imports and copies only those: 31MB, a sixteenth of the size.
   *
   * (The finished image is larger than that figure — around 317MB — because
   * the Node base image is most of it. The 500MB-to-31MB reduction is the part
   * this project controls; the base image is the floor beneath it.)
   *
   * SECURITY, and the reason this matters beyond image size: everything left
   * out of the image is code that cannot be executed inside the container if
   * someone finds a way to run something there. A production image that ships a
   * compiler, a linter and a full cloud SDK hands an intruder a toolkit. The
   * collectors are deliberately absent from the dashboard image for exactly
   * this reason — the process that serves HTTP has no ability to call AWS.
   *
   * The cost is one piece of manual work in the Dockerfile: tracing does not
   * pick up `public/` or the static assets under `.next/static`, because
   * nothing imports them, so those are copied explicitly. Miss that step and
   * the site renders unstyled. It is called out in a comment there.
   */
  output: "standalone",

  /**
   * Security response headers.
   *
   * These are the ones with no per-request component, which is why they belong
   * here rather than in proxy.ts: a header whose value never changes does not
   * need code to run on every request to produce it, and setting it here
   * covers the static assets that proxy.ts deliberately skips.
   *
   * The Content-Security-Policy is the exception and lives in proxy.ts,
   * because it carries a fresh nonce per response.
   *
   * `X-Powered-By` is not in this list because Next sends it by default and it
   * is removed separately below.
   */
  async headers() {
    return [
      {
        // Every path, including static assets and API routes.
        source: "/:path*",
        headers: [
          {
            // Stops the browser guessing a response's type from its bytes when
            // the declared Content-Type looks wrong. Without it, a file that an
            // endpoint returns as JSON but which happens to begin with HTML can
            // be sniffed as HTML and executed in the origin's context — turning
            // any endpoint that echoes user-controlled data into a scripting
            // vector.
            key: "X-Content-Type-Options",
            value: "nosniff",
          },
          {
            // Clickjacking defence for browsers that predate the CSP
            // `frame-ancestors` directive, which proxy.ts also sets. Both
            // are present because they are not the same control in the same
            // browsers, and the modern one silently does nothing in the old
            // ones. The risk is concrete: the dashboard has a one-click
            // suppress control that only an admin sees, and an invisible frame
            // over a hostile page is how an admin gets tricked into using it.
            key: "X-Frame-Options",
            value: "DENY",
          },
          {
            // Send the full URL as a referrer only to this origin; send only
            // the origin to same-protocol third parties, and nothing when
            // downgrading to HTTP.
            //
            // This matters more here than on an ordinary site because the URLs
            // are sensitive in themselves. A finding detail path contains a
            // base64url-encoded finding id, which encodes the ARN of a
            // misconfigured resource — so a leaked referrer tells a third party
            // the name of a bucket that is currently public.
            key: "Referrer-Policy",
            value: "strict-origin-when-cross-origin",
          },
          {
            // Switches off browser features this application never uses. The
            // dashboard has no camera, microphone, geolocation or payment
            // functionality, so denying them costs nothing and means an
            // injected script cannot reach for them either.
            key: "Permissions-Policy",
            value: [
              "camera=()",
              "microphone=()",
              "geolocation=()",
              "payment=()",
              "usb=()",
              "interest-cohort=()",
            ].join(", "),
          },
          {
            // Instructs the browser to use HTTPS for this origin for a year.
            //
            // Browsers ignore this header when it arrives over plain HTTP, so
            // it is inert on the current NodePort deployment and becomes active
            // the moment the dashboard is served over TLS — which is the right
            // shape for a header whose failure mode is being forgotten at the
            // point it starts to matter. `preload` is deliberately omitted:
            // submitting a domain to the browser preload list is close to
            // irreversible and is not a decision a portfolio project should
            // bake in.
            key: "Strict-Transport-Security",
            value: "max-age=31536000; includeSubDomains",
          },
          {
            // Isolates this origin's browsing context group from any window
            // that opened it, which blocks the cross-window scripting and
            // reference-leaking attacks available to a page that opened this
            // one via `window.open`.
            key: "Cross-Origin-Opener-Policy",
            value: "same-origin",
          },
          {
            // Refuses to let other origins embed this application's responses
            // as a subresource — an `<img>`, a `<script>`, a stylesheet. That
            // is the defence against cross-site leak techniques that infer
            // content from whether such a load succeeds or fails.
            key: "Cross-Origin-Resource-Policy",
            value: "same-origin",
          },
        ],
      },
    ];
  },

  /**
   * Removes the `X-Powered-By: Next.js` header.
   *
   * Not a serious control on its own — anyone can fingerprint a Next
   * application from its markup in a few seconds — but announcing the exact
   * framework serving a page is free reconnaissance, and there is no reason to
   * volunteer it. A tool that reports on other people's information disclosure
   * should not lead with its own.
   */
  poweredByHeader: false,
};

export default nextConfig;
