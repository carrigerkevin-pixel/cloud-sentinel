/**
 * CloudSentinel — Kubernetes deployment driver.
 *
 * Builds the container images and deploys the project into a local Kubernetes
 * cluster, in the order the manifests in k8s/ require.
 *
 *   npm run k8s:cluster    create the local kind cluster (once)
 *   npm run k8s:build      build both images and load them into the cluster
 *   npm run k8s:up         generate secrets if needed, then deploy everything
 *   npm run k8s:status     what is running
 *   npm run k8s:logs       follow the dashboard's logs
 *   npm run k8s:down       remove the workloads, keep the data
 *   npm run k8s:down -- --purge   remove everything including the database
 *
 * Where it sits in the architecture: pure plumbing, in the same spirit as
 * scripts/ml.ts. Every decision about *what* is deployed lives in the YAML under
 * k8s/; this file only decides the order, generates the secrets that must never
 * be committed, and waits for each step before starting the next.
 *
 * ---------------------------------------------------------------------------
 * Why a script rather than `kubectl apply -f k8s/`
 * ---------------------------------------------------------------------------
 *
 * Three things a bare `apply` cannot do, each of which would otherwise become a
 * paragraph of instructions in the README that somebody eventually skips.
 *
 * 1. **Ordering.** The manifests have hard dependencies: the namespace must
 *    exist before anything in it, the database before the migration, and the
 *    migration before the dashboard — whose pods query tables the migration
 *    creates. `kubectl apply -f k8s/` submits them in filename order and
 *    returns immediately, so the migration Job starts against a database that
 *    is still initialising and the dashboard starts against an empty schema.
 *    This script waits for each stage to be genuinely ready.
 *
 * 2. **Secrets.** A password, a JWT signing key and a TLS keypair have to exist
 *    before the pods start, and none of them may be committed. They are
 *    generated here, on first deploy only.
 *
 * 3. **A Job's spec is immutable.** Re-deploying has to delete the previous
 *    migration Job first; applying it again unchanged fails with a "field is
 *    immutable" error, which reads like a bug in the manifest rather than an
 *    ordinary consequence of running the command twice.
 *
 * ---------------------------------------------------------------------------
 * SECURITY
 * ---------------------------------------------------------------------------
 *
 * Every child process is spawned with `shell: false` and a fixed argument list,
 * so nothing can be interpreted as shell syntax. The one place a shell is used
 * — certificate generation — runs a hard-coded script inside a container with
 * no value from the command line interpolated into it.
 *
 * Secret values are written to `kubectl` over **stdin** as a manifest, never
 * passed as `--from-literal=KEY=value` arguments. On a shared machine the
 * process list is world-readable, so a command line containing the JWT signing
 * key hands it to any other user for as long as the command runs — and it lands
 * in the shell history besides. This is the same reasoning that makes
 * `npm run user:create` prompt for a password instead of taking it as an
 * argument.
 *
 * Exit status: 0 on success, 1 on a failed step, 2 for a bad command.
 */

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** The namespace every object is deployed into. Matches k8s/00-namespace.yaml. */
const NAMESPACE = "cloudsentinel";

/** Where generated TLS material is kept. Gitignored — see .gitignore. */
const TLS_DIR = join("k8s", "tls");

/**
 * Manifest files, in the order they must be applied.
 *
 * Listed explicitly rather than globbed. A glob would pick up any file dropped
 * into k8s/ — including the `tls/` working directory and any experiment left
 * behind — and would order them by name, which happens to be correct today only
 * because the numbering was chosen to make it so. Naming them here means the
 * order is a decision rather than a coincidence.
 */
const MANIFESTS = {
  namespace: join("k8s", "00-namespace.yaml"),
  postgres: join("k8s", "10-postgres.yaml"),
  migrate: join("k8s", "20-migrate-job.yaml"),
  app: join("k8s", "30-app.yaml"),
  networkPolicy: join("k8s", "40-networkpolicy.yaml"),
} as const;

/** The kind cluster definition, used only on the kind path. */
const KIND_CONFIG = join("k8s", "kind-cluster.yaml");

/** Image tags, matching the `image:` fields in the manifests. */
const IMAGES = {
  app: "cloudsentinel:app",
  tools: "cloudsentinel:tools",
} as const;

/**
 * The throwaway image certificate generation runs in.
 *
 * Built from the `certgen` stage of this project's own Dockerfile, which is the
 * project's base image plus the OpenSSL command line. The reasoning for that —
 * why not the host's openssl, why not the postgres or node images, and why not
 * a community image such as `alpine/openssl` — is written out at that stage.
 *
 * It is built on demand by {@link ensureCertificates} rather than by
 * `npm run k8s:build`, because it is needed once per deployment at most and is
 * not part of what gets deployed.
 */
const OPENSSL_IMAGE = "cloudsentinel:certgen";

/** Terminal colours, matching the other scripts in this directory. */
const style = {
  bold: (text: string) => `\x1b[1m${text}\x1b[0m`,
  dim: (text: string) => `\x1b[90m${text}\x1b[0m`,
  red: (text: string) => `\x1b[31m${text}\x1b[0m`,
  green: (text: string) => `\x1b[32m${text}\x1b[0m`,
  yellow: (text: string) => `\x1b[33m${text}\x1b[0m`,
};

// ---------------------------------------------------------------------------
// Running commands
// ---------------------------------------------------------------------------

/**
 * Runs a command with its output streamed to the terminal.
 *
 * `shell: false` (the default) is load-bearing: arguments reach the child as an
 * argv array, so nothing in them can be parsed as a pipe, a redirect, or a
 * command separator.
 *
 * @param command - executable to run.
 * @param args - arguments, as argv entries.
 * @param stdin - optional text written to the child's standard input. Used for
 *   secret manifests, so their values never appear in a command line.
 * @returns the child's exit code, or 1 if it was killed by a signal.
 */
function run(command: string, args: string[], stdin?: string): Promise<number> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      stdio: [stdin === undefined ? "inherit" : "pipe", "inherit", "inherit"],
    });

    child.on("error", reject);
    child.on("close", (code) => resolvePromise(code ?? 1));

    if (stdin !== undefined) {
      child.stdin?.end(stdin);
    }
  });
}

/**
 * Runs a command and captures its output instead of streaming it.
 *
 * Used for the small queries this script makes about cluster state — which
 * context is active, whether a Secret already exists — where the answer is
 * needed as a value rather than shown to the reader.
 *
 * @returns the exit code and the trimmed standard output. A non-zero code is
 *   returned rather than thrown: "this object does not exist" is an ordinary
 *   answer here, not a failure.
 */
function capture(
  command: string,
  args: string[],
): Promise<{ code: number; stdout: string }> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      stdio: ["ignore", "pipe", "ignore"],
    });

    let stdout = "";
    child.stdout?.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });

    child.on("error", reject);
    child.on("close", (code) =>
      resolvePromise({ code: code ?? 1, stdout: stdout.trim() }),
    );
  });
}

/**
 * Runs a step and aborts the whole deployment if it fails.
 *
 * Deployment steps are strictly ordered and each depends on the last, so
 * continuing after a failure produces a cascade of errors whose first cause has
 * already scrolled off the screen. Stopping at the first one keeps the actual
 * problem as the last thing printed.
 *
 * @throws {StepError} if the command exits non-zero.
 */
async function step(
  description: string,
  command: string,
  args: string[],
  stdin?: string,
): Promise<void> {
  console.error(style.bold(`\n> ${description}`));
  // The echoed command is for orientation, not for copying: the `kubectl run`
  // behind `k8s:user` carries a whole pod specification as a single argument
  // several thousand characters long, which buries every other line of output.
  // Long arguments are elided rather than the line being dropped, so the shape
  // of the command stays visible.
  const shown = args
    .map((arg) => (arg.length > 120 ? `${arg.slice(0, 117)}...` : arg))
    .join(" ");
  console.error(style.dim(`  ${command} ${shown}`));

  const code = await run(command, args, stdin);
  if (code !== 0) {
    throw new StepError(`${description} failed (exit ${code})`);
  }
}

/** A deployment step that failed. Carries no stack — the message is the point. */
class StepError extends Error {}

// ---------------------------------------------------------------------------
// Cluster detection
// ---------------------------------------------------------------------------

/** Which kind of local cluster kubectl is currently pointed at. */
type ClusterKind = "kind" | "docker-desktop" | "other";

/**
 * Identifies the active cluster from the current kubectl context.
 *
 * This matters for exactly one behavioural difference, and it is not cosmetic:
 * **how a locally-built image reaches the cluster.** kind runs its nodes as
 * separate containers with their own containerd image store, so an image built
 * on the host is invisible to it until `kind load docker-image` copies it in.
 * Docker Desktop's Kubernetes shares the host's image store directly, so the
 * same step is unnecessary there and the command does not exist.
 *
 * Getting this wrong produces an `ErrImageNeverPull` on every pod, which is an
 * unhelpful way to discover the difference.
 *
 * @returns the detected kind. `other` for a real cluster or an unrecognised
 *   one, where images would have to come from a registry.
 */
async function clusterKind(): Promise<ClusterKind> {
  const { code, stdout } = await capture("kubectl", [
    "config",
    "current-context",
  ]);
  if (code !== 0) return "other";

  if (stdout.startsWith("kind-")) return "kind";
  if (stdout === "docker-desktop") return "docker-desktop";
  return "other";
}

/**
 * Fails early with an actionable message if no cluster is reachable.
 *
 * Without this, the first `kubectl apply` fails with a connection-refused error
 * mentioning localhost:8080 — the default API server address kubectl falls back
 * to when it has no context at all — which sends people looking for a service
 * on port 8080 rather than for a missing cluster.
 *
 * @throws {StepError} when the API server cannot be reached.
 */
async function requireCluster(): Promise<ClusterKind> {
  const { code } = await capture("kubectl", [
    "cluster-info",
    "--request-timeout=10s",
  ]);

  if (code !== 0) {
    throw new StepError(
      "No Kubernetes cluster is reachable.\n\n" +
        "  Create the local one with:   npm run k8s:cluster\n" +
        "  (needs `kind`, see k8s/kind-cluster.yaml)\n\n" +
        "  Or enable Kubernetes in Docker Desktop:\n" +
        "  Settings -> Kubernetes -> Enable Kubernetes -> Apply & restart.",
    );
  }

  return clusterKind();
}

// ---------------------------------------------------------------------------
// TLS material
// ---------------------------------------------------------------------------

/**
 * The hostnames the database certificate must be valid for.
 *
 * All four spellings Kubernetes DNS resolves for the `cloudsentinel-db`
 * Service. The application connects using the short name, but the certificate
 * covers every form so that a future change to a fully-qualified name does not
 * turn into a hostname-verification failure that looks like a TLS bug.
 *
 * This list is the reason a certificate cannot simply be reused from somewhere
 * else: `lib/db/client.ts` verifies certificates properly, which means the name
 * in the certificate has to match the name being connected to.
 */
const DB_SAN = [
  "DNS:cloudsentinel-db",
  "DNS:cloudsentinel-db.cloudsentinel",
  "DNS:cloudsentinel-db.cloudsentinel.svc",
  "DNS:cloudsentinel-db.cloudsentinel.svc.cluster.local",
].join(",");

/**
 * Generates a private certificate authority and a server certificate for the
 * database, if they do not already exist.
 *
 * The whole apparatus exists because lib/db/client.ts requires verified TLS for
 * any non-loopback database, and in a cluster the database is always
 * non-loopback. The alternative — a switch that skips verification for
 * "internal" hosts — was rejected: it produces a connection that is encrypted
 * but unauthenticated, which anything able to answer on the Service address can
 * terminate and read. Generating a real certificate satisfies the rule honestly
 * instead of disabling it.
 *
 * Generation runs inside a container rather than against the host's OpenSSL,
 * for the portability reason explained on {@link OPENSSL_IMAGE}. The shell
 * script below is a fixed literal with nothing interpolated into it from the
 * command line.
 *
 * Existing files are left alone. Reissuing the certificate while the database
 * is running would leave the server presenting a certificate signed by an
 * authority the clients no longer hold, and every connection would fail
 * verification — so this is deliberately not a "refresh" operation. Delete
 * k8s/tls/ to force a new one, and re-create the secrets with it.
 *
 * @throws {StepError} if OpenSSL fails.
 */
async function ensureCertificates(): Promise<void> {
  const caCert = join(TLS_DIR, "ca.crt");
  const serverCert = join(TLS_DIR, "tls.crt");

  if (existsSync(caCert) && existsSync(serverCert)) {
    console.error(
      style.dim(`  TLS material already present in ${TLS_DIR}, keeping it`),
    );
    return;
  }

  mkdirSync(TLS_DIR, { recursive: true });

  // Built here rather than in `npm run k8s:build`: this image never reaches the
  // cluster, and on a repeat deployment the certificates already exist so this
  // whole function returns before reaching it.
  await step("Building the certificate generator", "docker", [
    "build",
    "--target",
    "certgen",
    "-t",
    OPENSSL_IMAGE,
    ".",
  ]);

  // `-nodes` leaves the private keys unencrypted, which is correct here: a
  // passphrase would have to be supplied to Postgres at every start, so it
  // would end up stored beside the key it protects. The key is protected by
  // being in a Kubernetes Secret and mounted 0640, not by a passphrase.
  //
  // 825 days is the maximum lifetime browsers and TLS libraries accept for a
  // server certificate. Nothing here is browser-facing, but staying inside the
  // limit means this material behaves the same way a real certificate would.
  const script = [
    "set -e",
    "cd /tls",

    "openssl req -x509 -newkey rsa:4096 -sha256 -days 825 -nodes" +
      " -keyout ca.key -out ca.crt" +
      ' -subj "/O=CloudSentinel/CN=CloudSentinel Local CA"',

    "openssl req -newkey rsa:2048 -nodes -keyout tls.key -out tls.csr" +
      ' -subj "/O=CloudSentinel/CN=cloudsentinel-db"',

    // The extensions file, rather than -addext, so this works across the
    // OpenSSL versions that ship in different base images. `serverAuth` and the
    // SAN list are what make the certificate usable for hostname verification;
    // a certificate with only a CN is rejected by modern TLS stacks.
    "printf '%s\\n' " +
      "'basicConstraints=CA:FALSE' " +
      "'keyUsage=digitalSignature,keyEncipherment' " +
      "'extendedKeyUsage=serverAuth' " +
      `'subjectAltName=${DB_SAN}' > server.ext`,

    "openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key" +
      " -CAcreateserial -out tls.crt -days 825 -sha256 -extfile server.ext",

    "rm -f tls.csr server.ext ca.srl",
    "echo 'generated CA and server certificate'",
  ].join("\n");

  await step("Generating the database TLS certificate", "docker", [
    "run",
    "--rm",
    // Run as the invoking user on Linux and macOS.
    //
    // Without this the container runs as root, and OpenSSL writes the private
    // key mode 0600 owned by root into the bind-mounted host directory. The
    // very next thing this script does is read that file back to build the
    // Secret — as the ordinary user — which fails with EACCES.
    //
    // The reason this is easy to miss: Docker Desktop on Windows does not map
    // ownership through a bind mount, so the files simply appear owned by the
    // developer and everything works. The failure exists only on Linux, which
    // means only CI sees it. It was in fact CI that caught it.
    //
    // `process.getuid` is undefined on Windows, which is the check being made
    // here — there is no meaningful uid to pass there, and passing one would
    // break the Docker Desktop path that already works.
    ...(typeof process.getuid === "function"
      ? ["--user", `${process.getuid()}:${process.getgid?.() ?? 0}`]
      : []),
    // The host directory the material is written into. An absolute path is
    // required by Docker; `resolve` also normalises the Windows separators.
    "-v",
    `${resolve(TLS_DIR)}:/tls`,
    OPENSSL_IMAGE,
    "sh",
    "-c",
    script,
  ]);
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

/**
 * Reports whether a Secret already exists in the namespace.
 *
 * Used to make secret creation happen exactly once. Re-generating them on every
 * deploy would be actively harmful in two different ways:
 *
 *   - Regenerating the **database password** breaks the database. Postgres only
 *     reads `POSTGRES_PASSWORD` when it initialises an empty data directory;
 *     afterwards the password lives in the volume. A new value would leave the
 *     application authenticating with a password the database has never heard
 *     of, against a volume that is otherwise perfectly intact.
 *   - Regenerating the **JWT signing key** invalidates every session
 *     immediately, so every deploy would log everybody out.
 */
async function secretExists(name: string): Promise<boolean> {
  const { code } = await capture("kubectl", [
    "get",
    "secret",
    name,
    "-n",
    NAMESPACE,
  ]);
  return code === 0;
}

/**
 * Builds a Secret manifest.
 *
 * `stringData` rather than `data`, so values are given as plain text and
 * Kubernetes performs the base64 encoding. Encoding by hand here would add a
 * step whose only effect is to make the values look encrypted in a way they are
 * not — base64 is an encoding, not a protection, and treating it as one is a
 * recurring source of secrets pasted into places they should not be.
 *
 * The manifest is never written to disk. It goes straight to `kubectl` over
 * stdin, so no file containing a signing key is created even briefly.
 */
function secretManifest(name: string, values: Record<string, string>): string {
  const entries = Object.entries(values)
    .map(([key, value]) => {
      // Block scalar with an explicit indentation indicator. Certificates are
      // multi-line and would otherwise need escaping; `|-` preserves the
      // newlines and strips only the trailing one.
      const indented = value
        .split("\n")
        .map((line) => `    ${line}`)
        .join("\n");
      return `  ${key}: |-\n${indented}`;
    })
    .join("\n");

  return [
    "apiVersion: v1",
    "kind: Secret",
    "metadata:",
    `  name: ${name}`,
    `  namespace: ${NAMESPACE}`,
    "  labels:",
    "    app.kubernetes.io/part-of: cloudsentinel",
    "type: Opaque",
    "stringData:",
    entries,
    "",
  ].join("\n");
}

/**
 * Creates the four secrets the deployment needs, if they are absent.
 *
 * The split into four is not tidiness — it is least privilege, and it is the
 * reason each workload mounts a different one:
 *
 *   cloudsentinel-db      the database password. Needed by Postgres, the
 *                         migration Job and the dashboard.
 *   cloudsentinel-db-tls  the server certificate **and its private key**.
 *                         Mounted only by Postgres. Anything holding this key
 *                         can impersonate the database.
 *   cloudsentinel-ca      the authority certificate alone. Mounted by the
 *                         clients, which need to verify the server but must
 *                         never be able to be one. A CA certificate is public
 *                         by nature; the key beside it is not.
 *   cloudsentinel-app     the JWT signing key. Mounted only by the dashboard.
 *                         Anyone holding it can forge a token claiming to be
 *                         any user with any role, so the migration Job — which
 *                         has no use for it — never sees it.
 */
async function ensureSecrets(): Promise<void> {
  console.error(style.bold("\n> Ensuring secrets exist"));

  if (await secretExists("cloudsentinel-db")) {
    console.error(style.dim("  cloudsentinel-db already exists, keeping it"));
  } else {
    // 24 random bytes as hex. Generated rather than chosen: a memorable local
    // password is the one that gets reused somewhere that matters.
    const password = randomBytes(24).toString("hex");
    await step(
      "Creating the database password secret",
      "kubectl",
      ["apply", "-f", "-"],
      secretManifest("cloudsentinel-db", { POSTGRES_PASSWORD: password }),
    );
  }

  if (await secretExists("cloudsentinel-app")) {
    console.error(style.dim("  cloudsentinel-app already exists, keeping it"));
  } else {
    // 48 bytes, comfortably above the 32-character minimum lib/auth/jwt.ts
    // enforces. HMAC-SHA256 has a 256-bit security level, so a shorter key
    // would be the weakest link in the chain.
    const jwtSecret = randomBytes(48).toString("base64");
    await step(
      "Creating the session signing secret",
      "kubectl",
      ["apply", "-f", "-"],
      secretManifest("cloudsentinel-app", {
        CLOUDSENTINEL_JWT_SECRET: jwtSecret,
      }),
    );
  }

  if (await secretExists("cloudsentinel-db-tls")) {
    console.error(style.dim("  cloudsentinel-db-tls already exists, keeping it"));
  } else {
    await step(
      "Creating the database TLS secret",
      "kubectl",
      ["apply", "-f", "-"],
      secretManifest("cloudsentinel-db-tls", {
        "tls.crt": readFileSync(join(TLS_DIR, "tls.crt"), "utf8"),
        "tls.key": readFileSync(join(TLS_DIR, "tls.key"), "utf8"),
        "ca.crt": readFileSync(join(TLS_DIR, "ca.crt"), "utf8"),
      }),
    );
  }

  if (await secretExists("cloudsentinel-ca")) {
    console.error(style.dim("  cloudsentinel-ca already exists, keeping it"));
  } else {
    await step(
      "Creating the certificate authority secret",
      "kubectl",
      ["apply", "-f", "-"],
      secretManifest("cloudsentinel-ca", {
        "ca.crt": readFileSync(join(TLS_DIR, "ca.crt"), "utf8"),
      }),
    );
  }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/** Creates the local kind cluster described by k8s/kind-cluster.yaml. */
async function cluster(): Promise<void> {
  await step("Creating the kind cluster", "kind", [
    "create",
    "cluster",
    "--config",
    KIND_CONFIG,
  ]);

  console.error(
    style.green("\nCluster created. Next: npm run k8s:build && npm run k8s:up"),
  );
}

/**
 * Builds both images and makes them visible to the cluster.
 *
 * The load step is conditional on the cluster kind — see {@link clusterKind}
 * for why kind needs it and Docker Desktop does not.
 */
async function build(): Promise<void> {
  await step("Building the dashboard image", "docker", [
    "build",
    "--target",
    "app",
    "-t",
    IMAGES.app,
    ".",
  ]);

  await step("Building the CLI image", "docker", [
    "build",
    "--target",
    "tools",
    "-t",
    IMAGES.tools,
    ".",
  ]);

  const kindOfCluster = await clusterKind();
  if (kindOfCluster === "kind") {
    for (const image of [IMAGES.app, IMAGES.tools]) {
      await step(`Loading ${image} into the kind cluster`, "kind", [
        "load",
        "docker-image",
        image,
        "--name",
        "cloudsentinel",
      ]);
    }
  } else {
    console.error(
      style.dim(
        "\n  Not a kind cluster — the images are already visible to it.",
      ),
    );
  }

  console.error(style.green("\nImages built. Next: npm run k8s:up"));
}

/**
 * Warns when the cluster will silently ignore the NetworkPolicy manifests.
 *
 * NetworkPolicy objects are accepted and stored by any cluster, whether or not
 * the network plugin implements them, and no warning is produced either way. A
 * network control believed to be active and in fact absent is worse than a
 * known gap — it is exactly the class of mistake this project exists to find —
 * so the ambiguity is resolved out loud rather than left to be assumed.
 */
function warnAboutNetworkPolicy(kindOfCluster: ClusterKind): void {
  if (kindOfCluster !== "docker-desktop") return;

  console.error(
    style.yellow(
      "\n  Note: Docker Desktop's Kubernetes does not enforce NetworkPolicy.\n" +
        "  The rules in k8s/40-networkpolicy.yaml are stored but inert here.\n" +
        "  They are enforced on kind and on any managed cluster.",
    ),
  );
}

/** Deploys everything, in dependency order, waiting at each stage. */
async function up(): Promise<void> {
  const kindOfCluster = await requireCluster();

  await step("Creating the namespace", "kubectl", [
    "apply",
    "-f",
    MANIFESTS.namespace,
  ]);

  await ensureCertificates();
  await ensureSecrets();

  await step("Deploying PostgreSQL", "kubectl", [
    "apply",
    "-f",
    MANIFESTS.postgres,
  ]);

  // Waits for the pod to pass its readiness probe, which runs `pg_isready` —
  // so this returns when the database can actually answer a query, not merely
  // when the container has started. The migration begins immediately after.
  await step("Waiting for PostgreSQL to be ready", "kubectl", [
    "rollout",
    "status",
    "statefulset/cloudsentinel-db",
    "-n",
    NAMESPACE,
    "--timeout=180s",
  ]);

  // A Job's spec is immutable, so a re-deploy must remove the previous one.
  // `--ignore-not-found` makes the first deploy behave the same as the rest.
  await step("Clearing any previous migration Job", "kubectl", [
    "delete",
    "job",
    "cloudsentinel-migrate",
    "-n",
    NAMESPACE,
    "--ignore-not-found",
  ]);

  await step("Running database migrations", "kubectl", [
    "apply",
    "-f",
    MANIFESTS.migrate,
  ]);

  // If the migration fails, the deployment stops here — before the dashboard is
  // updated. That ordering is the point: a schema change that did not apply
  // leaves the previous version of the application running against the schema
  // it was written for, rather than a new version against a schema it does not
  // recognise.
  await step("Waiting for migrations to complete", "kubectl", [
    "wait",
    "--for=condition=complete",
    "job/cloudsentinel-migrate",
    "-n",
    NAMESPACE,
    "--timeout=180s",
  ]);

  await step("Applying network policy", "kubectl", [
    "apply",
    "-f",
    MANIFESTS.networkPolicy,
  ]);

  await step("Deploying the dashboard", "kubectl", [
    "apply",
    "-f",
    MANIFESTS.app,
  ]);

  await step("Waiting for the dashboard to roll out", "kubectl", [
    "rollout",
    "status",
    "deployment/cloudsentinel-app",
    "-n",
    NAMESPACE,
    "--timeout=180s",
  ]);

  warnAboutNetworkPolicy(kindOfCluster);

  console.error(style.green("\nDeployed. The dashboard is at http://localhost:30080"));
  console.error(
    style.dim(
      "\nThere is no sign-up page, so create an account before logging in:\n" +
        "  npm run k8s:user -- you@example.com --admin\n",
    ),
  );
}

/**
 * Creates a dashboard account inside the cluster.
 *
 * Runs `scripts/user.ts` in the `tools` image as a one-off pod, because there
 * is deliberately no sign-up page — accounts exist only via this CLI. Attached
 * to a terminal (`-it`) so the password prompt can suppress echo, which is the
 * whole reason the CLI prompts rather than taking the password as an argument:
 * an argument lands in the shell history and the process list.
 *
 * @param args - forwarded to the CLI, e.g. `you@example.com --admin`.
 */
async function user(args: string[]): Promise<void> {
  await requireCluster();

  await step(
    "Creating a dashboard user",
    "kubectl",
    [
      "run",
      `cloudsentinel-user-${Date.now()}`,
      "-n",
      NAMESPACE,
      "--rm",
      "-it",
      "--restart=Never",
      "--image",
      IMAGES.tools,
      "--image-pull-policy=Never",
      // The pod needs the same database configuration as the migration Job.
      // Passed as an overrides document because `kubectl run` has no flag for
      // mounting a secret volume, which the CA certificate requires.
      "--overrides",
      JSON.stringify(userPodOverrides(args)),
    ],
  );
}

/**
 * The pod specification for a one-off `scripts/user.ts` run.
 *
 * Separated from {@link user} because it is data rather than logic, and because
 * the shape is long enough to bury the command it belongs to. It mirrors the
 * container in k8s/20-migrate-job.yaml: same image, same database environment,
 * same CA mount, same hardening — the differences are the command and the fact
 * that it is interactive.
 */
function userPodOverrides(args: string[]): unknown {
  return {
    apiVersion: "v1",
    metadata: {
      labels: {
        // Declares this pod a database client. k8s/40-networkpolicy.yaml
        // selects on exactly this label to permit port 5432, so without it the
        // connection is dropped and the CLI reports a connection timeout with
        // nothing to indicate the network policy was responsible.
        "cloudsentinel.dev/db-client": "true",
        "app.kubernetes.io/part-of": "cloudsentinel",
      },
    },
    spec: {
      securityContext: {
        runAsUser: 1000,
        runAsGroup: 1000,
        runAsNonRoot: true,
        seccompProfile: { type: "RuntimeDefault" },
      },
      containers: [
        {
          name: "user",
          image: IMAGES.tools,
          imagePullPolicy: "Never",
          command: ["node", "scripts/user.ts", "create", ...args],
          // `stdin` and `tty` are deliberately NOT set here. `kubectl run -it`
          // sets them itself, and it turns them *off* when it finds no terminal
          // attached — a piped or redirected invocation, or CI. Forcing them on
          // in the overrides desynchronises the two: the pod is created asking
          // for a TTY while kubectl streams a separate stderr, and the API
          // server rejects the attach with "tty and stderr cannot both be
          // true". Letting the flags own the decision keeps both paths working.
          env: [
            { name: "POSTGRES_HOST", value: "cloudsentinel-db" },
            { name: "POSTGRES_PORT", value: "5432" },
            { name: "POSTGRES_USER", value: "cloudsentinel" },
            { name: "POSTGRES_DB", value: "cloudsentinel" },
            {
              name: "POSTGRES_PASSWORD",
              valueFrom: {
                secretKeyRef: {
                  name: "cloudsentinel-db",
                  key: "POSTGRES_PASSWORD",
                },
              },
            },
            { name: "CLOUDSENTINEL_ALLOW_REMOTE_DB", value: "1" },
            {
              name: "POSTGRES_CA_CERT_FILE",
              value: "/etc/cloudsentinel-tls/ca.crt",
            },
          ],
          volumeMounts: [
            {
              name: "ca",
              mountPath: "/etc/cloudsentinel-tls",
              readOnly: true,
            },
          ],
          securityContext: {
            allowPrivilegeEscalation: false,
            privileged: false,
            capabilities: { drop: ["ALL"] },
            readOnlyRootFilesystem: true,
          },
        },
      ],
      volumes: [
        // The public CA only — never the server's private key. See the note in
        // k8s/20-migrate-job.yaml.
        { name: "ca", secret: { secretName: "cloudsentinel-ca" } },
      ],
    },
  };
}

/** Prints what is running. */
async function status(): Promise<void> {
  await requireCluster();

  await step("Workloads", "kubectl", [
    "get",
    "all,pvc,networkpolicy",
    "-n",
    NAMESPACE,
  ]);
}

/** Follows the dashboard's logs across both replicas. */
async function logs(): Promise<void> {
  await requireCluster();

  await step("Dashboard logs", "kubectl", [
    "logs",
    "-n",
    NAMESPACE,
    "-l",
    "app.kubernetes.io/name=cloudsentinel-app",
    "--all-containers",
    "--tail=100",
    "--follow",
  ]);
}

/**
 * Removes the deployment.
 *
 * The default keeps the namespace, the secrets and the PersistentVolumeClaim,
 * so scan history survives and `npm run k8s:up` brings everything back with the
 * same data and the same signing key. Only `--purge` deletes the namespace,
 * which takes the volume with it.
 *
 * That default is deliberate. The `first_seen_at` date on a finding — what lets
 * the dashboard say "public since the 4th of August" — is the one thing in this
 * project that cannot be regenerated by re-running a command, so the routine
 * command must not be the one that destroys it. Deleting data should require
 * having said so.
 */
async function down(purge: boolean): Promise<void> {
  await requireCluster();

  if (purge) {
    console.error(
      style.yellow(
        "\n  --purge: deleting the namespace, including the database volume.\n" +
          "  All stored scans, findings, users and anomaly runs will be lost.",
      ),
    );

    await step("Deleting the namespace", "kubectl", [
      "delete",
      "namespace",
      NAMESPACE,
      "--ignore-not-found",
      "--wait=true",
    ]);

    console.error(style.green("\nRemoved, including all data."));
    return;
  }

  // Named workload types rather than `delete all`: `all` does not include the
  // PersistentVolumeClaim, but it is worth being explicit about what is going
  // rather than relying on a shorthand whose coverage is easy to misremember.
  await step("Removing workloads", "kubectl", [
    "delete",
    "deployment,statefulset,job,service",
    "--all",
    "-n",
    NAMESPACE,
    "--ignore-not-found",
  ]);

  console.error(
    style.green("\nWorkloads removed. The database volume and secrets remain."),
  );
  console.error(
    style.dim("Use `npm run k8s:down -- --purge` to delete those too."),
  );
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

function printUsage(): void {
  console.error(
    [
      style.bold("CloudSentinel — Kubernetes deployment"),
      "",
      "  npm run k8s:cluster            create the local kind cluster",
      "  npm run k8s:build              build both images, load them in",
      "  npm run k8s:up                 deploy everything",
      "  npm run k8s:user -- <email>    create a dashboard account",
      "  npm run k8s:status             show what is running",
      "  npm run k8s:logs               follow the dashboard logs",
      "  npm run k8s:down               remove workloads, keep the data",
      "  npm run k8s:down -- --purge    remove everything, data included",
      "",
    ].join("\n"),
  );
}

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);

  switch (command) {
    case "cluster":
      await cluster();
      break;
    case "build":
      await build();
      break;
    case "up":
      await up();
      break;
    case "user":
      await user(args);
      break;
    case "status":
      await status();
      break;
    case "logs":
      await logs();
      break;
    case "down":
      await down(args.includes("--purge"));
      break;
    default:
      printUsage();
      process.exitCode = 2;
      return;
  }
}

main().catch((error: unknown) => {
  // A failed step prints its own output already, so only the summary is added
  // here. Anything else is unexpected and shown in full.
  const message = error instanceof Error ? error.message : String(error);
  console.error(`\n${style.red("Failed:")} ${message}`);
  process.exitCode = 1;
});
