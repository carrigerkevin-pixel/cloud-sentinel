# CloudSentinel — container images.
#
# What this is: a multi-stage build producing *two* runtime images from one
# source tree.
#
#   cloudsentinel:app    the Next.js dashboard and its API routes. Long-running
#                        HTTP server. This is what k8s/40-app.yaml deploys.
#
#   cloudsentinel:tools  the command-line side of the project — database
#                        migrations, user administration, the scanner, anomaly
#                        ingestion. Runs to completion and exits. This is what
#                        k8s/30-migrate-job.yaml runs.
#
# Where this fits in the architecture: it is the packaging boundary. Everything
# above it (collectors, rule engine, ML layer, dashboard) is unaware it runs in
# a container; everything below it (k8s/) is unaware of how the code is built.
#
# Usage:
#
#   docker build --target app   -t cloudsentinel:app   .
#   docker build --target tools -t cloudsentinel:tools .
#   npm run k8s:build                                   # builds both
#
# ===========================================================================
# Why two images rather than one
# ===========================================================================
#
# It would be simpler to ship a single image containing everything and pick a
# command at run time. That is rejected on security grounds, and the reasoning
# is the same principle the rule engine looks for in other people's IAM
# policies: a workload should not hold a capability it does not use.
#
# The dashboard image physically cannot migrate the database, create an admin
# user, or call AWS — not because it is configured not to, but because
# `scripts/` and the AWS SDK are not in the image. If the web process is ever
# compromised, `node scripts/user.ts create --admin` is not an available move,
# and neither is reaching into the simulated cloud account. Confining those
# abilities to a short-lived Job that exists only during a deployment is a
# meaningfully smaller target than leaving them resident in a public-facing
# server for as long as it runs.
#
# The `output: "standalone"` setting in next.config.ts is what makes this cheap:
# Next traces the files the server actually imports, so the app image drops from
# a ~500MB dependency tree to ~31MB without anything being pruned by hand.


# ===========================================================================
# Stage: base — the common foundation
# ===========================================================================
#
# Node 24 specifically, and it is not interchangeable. This project imports
# `.ts` files directly at run time and relies on Node's built-in type
# stripping to execute them; scripts/db.ts, scripts/scan.ts and everything they
# import are never compiled to JavaScript. An older major would fail to load a
# single file. That is the same reason .github/workflows/ci.yml pins node 24.
#
# Alpine keeps the image small. The trade-off is musl rather than glibc, which
# occasionally matters for packages shipping prebuilt native binaries — so
# libc6-compat is installed below, which is what Next's own image guidance
# recommends and what its optional image codecs expect to find.
FROM node:24-alpine AS base

RUN apk add --no-cache libc6-compat

WORKDIR /app

# Next.js phones home with anonymous build and usage statistics unless told not
# to. Disabled everywhere: a security tool should not make unannounced outbound
# connections, and a container build should be reproducible offline.
ENV NEXT_TELEMETRY_DISABLED=1


# ===========================================================================
# Stage: deps — dependency installation
# ===========================================================================
#
# Only the manifests are copied here, before any source. That ordering is the
# whole point of the stage: Docker caches each layer against the files it was
# built from, so editing a source file leaves this layer untouched and the
# install is skipped entirely. Copying source first would reinstall every
# dependency on every code change.
FROM base AS deps

# `npm ci` rather than `npm install`: it installs exactly what the lockfile
# pins and fails if the lockfile and package.json disagree, so an image can
# never silently contain a different dependency tree than the one reviewed.
#
# NOTE for this repository specifically: package-lock.json must be generated on
# Linux. A lockfile produced by a plain install on the Windows dev machine drops
# the @emnapi entries that @tailwindcss/oxide-wasm32-wasi needs, and this line
# is where that failure surfaces, as "Missing: @emnapi/core from lock file".
# `npm run relock` regenerates it correctly.
COPY package.json package-lock.json ./
RUN npm ci


# ===========================================================================
# Stage: builder — compile the dashboard
# ===========================================================================
FROM base AS builder

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# SECURITY: a placeholder signing key, used only to get through the build.
#
# lib/auth/jwt.ts refuses to load without CLOUDSENTINEL_JWT_SECRET set to at
# least 32 characters, and the production build imports it while prerendering
# pages. So the build needs *a* value — but it must not be a value anything
# trusts.
#
# Two properties make this safe, and both are load-bearing:
#
#   1. The secret is read lazily, inside a function, on each call. Next
#      therefore never inlines it into the compiled output, and nothing built
#      here carries it. (Were it read at module scope, this value would be
#      baked into the bundle and every deployment would share a publicly known
#      signing key — which is exactly how forgeable sessions ship.)
#   2. It is set as a shell variable on this single command rather than with
#      `ENV`. An `ENV` would be recorded in the image's metadata and reported by
#      Docker's own build linter as a secret in the environment — correctly, in
#      general, even though this particular value is a placeholder. Scoping it
#      to one command means it exists for the duration of the build step and is
#      written into no layer, no metadata, and no runtime image. The real secret
#      arrives at run time from a Kubernetes Secret.
#
# The value is written to be unmistakable if it ever does turn up somewhere.
RUN CLOUDSENTINEL_JWT_SECRET=build-time-placeholder-never-used-at-runtime \
    npm run build


# ===========================================================================
# Stage: app — the dashboard runtime
# ===========================================================================
FROM base AS app

ENV NODE_ENV=production

# SECURITY: remove npm from the runtime image.
#
# This image starts `node server.js` directly and never invokes a package
# manager, so npm is dead weight in it — and dead weight with unusual powers. It
# is a program whose entire purpose is to fetch remote code and execute install
# scripts, which is precisely the capability an intruder who lands in a
# container is looking for. Removing it is the same argument that keeps
# `scripts/` and the AWS SDK out of this image, applied to the tooling that
# comes with the base image rather than to the project's own code.
#
# It also removes real, currently-published vulnerabilities. npm vendors its own
# dependencies, and the CI image scan flagged a fixable CRITICAL in the `tar`
# copy bundled inside it (CVE-2026-59873) — a package this application never
# calls, reachable only through a tool it does not use. Deleting the tool is a
# better fix than tracking upstream's patch cadence for it.
RUN rm -rf /usr/local/lib/node_modules/npm \
           /usr/local/bin/npm \
           /usr/local/bin/npx

# SECURITY: run as an unprivileged user.
#
# A container's root is the host's root as far as several classes of container
# escape are concerned, and there is no reason for a web server to have it. The
# `node` user (uid 1000) already exists in the official image, so no account
# needs creating. k8s/40-app.yaml additionally sets `runAsNonRoot: true`, which
# makes the cluster *refuse to start* the pod if this line is ever removed —
# defence in depth, because a Dockerfile edit is easy to make by accident and a
# rejected pod is loud where a silently-root container is not.
USER node

# The three pieces of a standalone build, and all three are required.
#
# `server.js` plus its traced node_modules is what `standalone` produces. It
# does NOT include static assets, because nothing in the server graph imports
# them — Next expects them to be placed alongside. Omitting either of the last
# two copies produces a site that boots, serves HTML, and renders completely
# unstyled, which is a confusing failure to debug. `--chown` matters because the
# files are copied as root by default and this stage runs as `node`.
COPY --from=builder --chown=node:node /app/.next/standalone ./
COPY --from=builder --chown=node:node /app/.next/static ./.next/static
COPY --from=builder --chown=node:node /app/public ./public

# Bind to every interface *inside the container*. This is not the loopback
# discipline lib/db/client.ts and lib/aws/localstack.ts enforce being relaxed:
# a container has its own network namespace, so 0.0.0.0 here means "reachable
# from the pod network", and what is actually exposed outside the cluster is
# decided by the Service and NetworkPolicy in k8s/, not by this line. A server
# bound to 127.0.0.1 inside a pod is unreachable even by its own health probe.
ENV HOSTNAME=0.0.0.0
ENV PORT=3000
EXPOSE 3000

# Docker's own health check, for the plain `docker run` and Compose paths.
# Kubernetes ignores this and uses the probes in k8s/40-app.yaml instead.
#
# Written with Node's global fetch rather than curl or wget: neither is worth
# adding to the image just for this, and every package left out is one fewer
# tool available to anyone who gets a shell in the container.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/api/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# `node server.js` directly, with no npm wrapper. npm would sit in the process
# tree as PID 1 and swallow SIGTERM, so Kubernetes' graceful shutdown would time
# out and every pod would be SIGKILLed after its termination grace period —
# cutting off in-flight requests on every single deployment.
CMD ["node", "server.js"]


# ===========================================================================
# Stage: tools — the command-line runtime
# ===========================================================================
#
# Unlike `app`, this image carries real source rather than a bundle, because
# every CLI in scripts/ is executed as TypeScript by Node's type stripping.
# There is no build step to bundle it into.
#
# It intentionally has no default command and no exposed port. It is not a
# service: it is started with an explicit command, does one job, and exits.
FROM base AS tools

ENV NODE_ENV=production

# `--omit=dev` drops TypeScript, ESLint, Tailwind and the React type packages —
# none of which any CLI imports.
#
# It does NOT drop Next.js, React or the image codecs, because those are
# *production* dependencies of the dashboard and npm has no way to know this
# image never serves a page. Left alone they are 384MB of web framework — the
# Next runtime, React, `sharp`, and the SWC native compiler binaries — sitting
# in an image whose entire job is to run a migration and exit.
#
# That is not merely wasteful, it contradicts the reason this image is separate
# at all (see the header): a workload should not hold a capability it does not
# use. An image carrying a native compiler toolchain and a full server framework
# hands an intruder exactly the toolkit the `app` image was split apart to deny
# them.
#
# So they are removed explicitly. The alternative — installing a hand-written
# list of packages instead of using the lockfile — was rejected because it would
# give up the guarantee that every remaining dependency is the exact version
# package-lock.json pins. Deleting from a faithful install keeps that property
# for everything that stays.
#
# The list below is derived, not guessed: `lib/auth/session.ts` is the only file
# under lib/ or scripts/ that imports anything from Next or React, and it is
# reached solely from app/ routes, never from a command line entry point.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev \
    && rm -rf \
        node_modules/next \
        node_modules/@next \
        node_modules/@img \
        node_modules/sharp \
        node_modules/react \
        node_modules/react-dom \
        node_modules/styled-jsx \
        node_modules/@swc \
        node_modules/caniuse-lite \
    # And npm itself, once it has finished installing. Every command this image
    # runs is `node scripts/<something>.ts`; none of them shells out to a
    # package manager. The reasoning is the same as in the `app` stage above —
    # a tool for fetching and executing remote code has no business remaining in
    # a container that only migrates a database — and it removes the fixable
    # CRITICAL that CI's image scan finds in npm's vendored copy of `tar`.
    && rm -rf /usr/local/lib/node_modules/npm \
              /usr/local/bin/npm \
              /usr/local/bin/npx

# Only the directories the CLIs actually read. Listing them explicitly rather
# than copying the whole tree is deliberate: it means a new top-level directory
# has to be added here consciously to reach this image, instead of arriving
# unnoticed.
COPY --chown=node:node scripts ./scripts
COPY --chown=node:node lib ./lib
COPY --chown=node:node db ./db
COPY --chown=node:node fixtures/inventory.json ./fixtures/inventory.json

USER node

# Prove the prune above did not remove something a CLI needs.
#
# The dependency deletion is the most fragile line in this file: it is a
# hand-maintained list, and a future import that reaches React or Next from
# lib/ would break these commands at *deploy* time, inside a Kubernetes Job,
# where the symptom is a migration that will not start and a rollout that hangs.
# Failing the build instead turns that into an obvious error next to the line
# that caused it.
#
# Every module the containerised commands depend on is imported here. Importing
# lib/ modules rather than scripts/ is deliberate — a script executes its CLI
# body on import, which would try to reach a database that does not exist during
# a build. These modules only construct the connection pool lazily, so importing
# them opens no socket.
RUN node --input-type=module -e "\
    await import('/app/lib/db/migrate.ts'); \
    await import('/app/lib/db/scans.ts'); \
    await import('/app/lib/db/anomalies.ts'); \
    await import('/app/lib/db/users.ts'); \
    await import('/app/lib/rules/engine.ts'); \
    await import('/app/lib/collectors/inventory.ts'); \
    await import('/app/lib/anomalies/ingest.ts'); \
    console.log('tools image: CLI module graph loads');"

# No CMD. Running this image with no arguments should fail obviously rather
# than silently doing something — every use site names its own command, for
# example `node scripts/db.ts migrate`.


# ===========================================================================
# Stage: certgen — TLS material generation
# ===========================================================================
#
# A throwaway image holding the OpenSSL command line, used by `npm run k8s:up`
# to issue the private certificate authority and the database's server
# certificate. It is never deployed and never runs in the cluster.
#
# Why this stage exists rather than one of the alternatives:
#
#   - **Not the host's openssl.** On a normal Windows install OpenSSL arrives
#     only as part of Git for Windows and is not on the PATH that npm scripts
#     inherit, so a host-based approach works on Linux and CI and fails on the
#     machine this project is developed on.
#   - **Not the postgres or node images.** Both link against libssl but neither
#     ships the `openssl` binary, which is a genuinely surprising thing to
#     discover halfway through a deployment.
#   - **Not a third-party image such as `alpine/openssl`.** Pulling a community
#     image to generate the key material that secures the database is a
#     supply-chain decision, and a poor one for a project whose subject is
#     security. Everything here comes from the same official base image the rest
#     of the build already trusts.
#
# The cost is one `apk add` on first build, cached thereafter. Keeping it in its
# own stage is what stops the `openssl` binary from ending up in the `tools`
# image, where it would be one more tool available to anyone who got a shell in
# a container that has no use for it.
FROM base AS certgen

RUN apk add --no-cache openssl

# No CMD — scripts/k8s.ts supplies the generation script.
