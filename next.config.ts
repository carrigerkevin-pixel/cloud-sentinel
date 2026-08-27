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
};

export default nextConfig;
