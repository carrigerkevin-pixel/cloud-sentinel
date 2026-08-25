/**
 * CloudSentinel — PostgreSQL connection management.
 *
 * Owns the single connection pool the rest of the project shares, reads its
 * configuration from the environment, and provides the transaction helper every
 * write path uses.
 *
 * Where it sits in the architecture: the boundary between CloudSentinel's
 * in-memory model and durable storage. Nothing above this file knows the
 * database exists; nothing below it knows what a finding is.
 *
 *   ScanResult --> lib/db/scans.ts --> [ this file ] --> Postgres
 *
 * Entry points that reach this code: `npm run db:migrate`, `npm run db:status`,
 * and `npm run scan -- --save`.
 *
 * SECURITY, and the two things this file exists to get right:
 *
 * 1. **No credential ever appears in source, output, or an error message.** The
 *    password comes from the environment only. {@link describeConnection}
 *    exists so that logs and error text can say which database is being used
 *    without printing how to connect to it — a connection string in a stack
 *    trace ends up in a terminal buffer, a CI log, and eventually a screenshot.
 *
 * 2. **A remote database requires explicit opt-in.** By default the client
 *    refuses any host that is not loopback. The risk being prevented is
 *    specific and mundane: a `DATABASE_URL` left over in a shell from another
 *    project, quietly writing local test scans into a shared database — or
 *    worse, a migration running against one. That mirrors the loopback
 *    discipline lib/aws/localstack.ts already enforces for the AWS side, so the
 *    project holds itself to one rule rather than two.
 */

import { Pool } from "pg";
import type { PoolClient, QueryResultRow } from "pg";

import { loadEnvFile } from "../util/env.ts";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * Resolved connection settings.
 *
 * The password is deliberately not part of this shape. It is read straight from
 * the environment into the pool's own options and never stored anywhere it
 * could be logged, inspected, or accidentally serialized alongside a scan.
 */
export interface DatabaseConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  /** True when the host is loopback, so the connection never leaves the machine. */
  isLocal: boolean;
}

/** Hostnames that resolve to this machine and never touch a network. */
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

/**
 * Environment variable that permits connecting to a non-loopback database.
 *
 * Deliberately awkward to set by accident. Anyone who types this has decided to
 * point CloudSentinel at a shared database on purpose.
 */
const ALLOW_REMOTE = "CLOUDSENTINEL_ALLOW_REMOTE_DB";

/**
 * Reads connection settings from the environment.
 *
 * Two spellings are supported, in this order:
 *
 *   1. `DATABASE_URL` — a full `postgresql://` connection string. Standard, and
 *      what a hosting platform injects, so it wins when present.
 *   2. `POSTGRES_HOST` / `_PORT` / `_DB` / `_USER` / `_PASSWORD` — the discrete
 *      variables docker-compose.yml already uses, so a single `.env` configures
 *      both the container and the client with no duplication.
 *
 * @returns the resolved configuration.
 * @throws if the password is missing, or if the host is not loopback and
 *   {@link ALLOW_REMOTE} has not been set. Both are thrown rather than warned
 *   about: a scanner that silently connects somewhere unintended is worse than
 *   one that refuses to start.
 */
export function databaseConfig(): DatabaseConfig {
  // Reads .env on the first call only, and never overwrites a variable that is
  // already set. Done here rather than at module scope so that importing this
  // file has no side effects — a test can set its own environment first and
  // this will respect it.
  loadEnvFile();

  const url = process.env.DATABASE_URL;

  let host: string;
  let port: number;
  let database: string;
  let user: string;
  let password: string | undefined;

  if (url) {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      // The message names the variable but never quotes its value — the value
      // is the credential.
      throw new Error(
        "DATABASE_URL is not a valid connection URL. Expected the form " +
          "postgresql://user:password@host:5432/database",
      );
    }
    host = parsed.hostname;
    port = parsed.port ? Number(parsed.port) : 5432;
    database = parsed.pathname.replace(/^\//, "") || "cloudsentinel";
    user = decodeURIComponent(parsed.username) || "cloudsentinel";
    password = decodeURIComponent(parsed.password);
  } else {
    host = process.env.POSTGRES_HOST ?? "127.0.0.1";
    port = Number(process.env.POSTGRES_PORT ?? 5432);
    database = process.env.POSTGRES_DB ?? "cloudsentinel";
    user = process.env.POSTGRES_USER ?? "cloudsentinel";
    password = process.env.POSTGRES_PASSWORD;
  }

  if (!password) {
    throw new Error(
      "No database password configured. Copy .env.example to .env and set " +
        "POSTGRES_PASSWORD, then start the database with " +
        "`docker compose up -d db`.",
    );
  }

  const isLocal = LOOPBACK_HOSTS.has(host);
  if (!isLocal && process.env[ALLOW_REMOTE] !== "1") {
    throw new Error(
      `Refusing to connect to non-loopback database host "${host}". ` +
        "CloudSentinel defaults to a local database so that a stray " +
        "DATABASE_URL cannot write scan data into a shared environment. " +
        `Set ${ALLOW_REMOTE}=1 if this is intended.`,
    );
  }

  return { host, port, database, user, isLocal };
}

/**
 * Renders the connection for human-readable output, with no credential.
 *
 * Used in CLI banners and error messages. The password is never included, and
 * the format is deliberately not a valid connection string so it cannot be
 * copied out of a log and reused.
 */
export function describeConnection(config: DatabaseConfig): string {
  return `${config.user}@${config.host}:${config.port}/${config.database}`;
}

// ---------------------------------------------------------------------------
// Pool
// ---------------------------------------------------------------------------

/**
 * The process-wide pool, created on first use.
 *
 * A pool rather than a connection per query: opening a Postgres connection
 * costs a TCP handshake plus authentication, and a scan writes several hundred
 * rows. A module-level singleton is appropriate here because the CLIs are
 * short-lived, single-purpose processes — when the Next.js API arrives it will
 * share this same pool rather than opening its own.
 */
let pool: Pool | null = null;

/**
 * Returns the shared connection pool, creating it if necessary.
 *
 * @throws whatever {@link databaseConfig} throws, on the first call only.
 */
export function getPool(): Pool {
  if (pool) return pool;

  const config = databaseConfig();

  pool = new Pool({
    host: config.host,
    port: config.port,
    database: config.database,
    user: config.user,
    // Read directly from the environment into the driver, so the value is never
    // held in any structure this project defines.
    password: process.env.DATABASE_URL
      ? decodeURIComponent(new URL(process.env.DATABASE_URL).password)
      : process.env.POSTGRES_PASSWORD,

    // A local CLI needs a handful of connections at most. Leaving the default
    // of 10 open against a container that is also serving the dashboard is
    // wasteful for no benefit.
    max: 5,

    // Fail fast rather than hanging. Without this a stopped container makes
    // `npm run scan -- --save` appear to freeze, which reads as a bug in the
    // scanner rather than as "the database is not running".
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 10_000,

    // SECURITY: require TLS for anything that is not loopback. A loopback
    // connection never reaches a network interface, so TLS there would add
    // certificate management for no threat model. A remote one carries scan
    // findings — a list of exactly where an environment is weakest — and must
    // not cross a network in the clear.
    ssl: config.isLocal ? undefined : { rejectUnauthorized: true },
  });

  // `pg` emits 'error' on idle clients dropped by the server. Unhandled, this
  // event crashes the process — and it fires routinely when the database
  // container restarts, which during development is often. The pool discards
  // the broken client on its own; this listener exists only so the event has
  // somewhere to go.
  pool.on("error", (error: Error) => {
    console.error(`\x1b[33mDatabase pool error:\x1b[0m ${error.message}`);
  });

  return pool;
}

/**
 * Closes the pool, if one was opened.
 *
 * Node keeps the process alive while a pool holds open sockets, so a CLI that
 * forgets this hangs after printing its output. Safe to call when no pool was
 * ever created.
 */
export async function closePool(): Promise<void> {
  if (!pool) return;
  await pool.end();
  pool = null;
}

// ---------------------------------------------------------------------------
// Query helpers
// ---------------------------------------------------------------------------

/**
 * Runs a parameterised query against the pool.
 *
 * SECURITY: `params` are sent separately from the SQL text, so the driver
 * never interpolates them into the statement. Every call site in this project
 * passes values this way rather than building SQL with template literals —
 * which is how a tool that reports on other people's security failures avoids
 * shipping an SQL injection of its own. Resource names and ARNs come from an
 * AWS account CloudSentinel does not control, and are exactly the kind of
 * attacker-influenced string that makes string-concatenated SQL dangerous.
 *
 * @param text - the SQL, using `$1`, `$2` placeholders.
 * @param params - values for those placeholders.
 */
export async function query<T extends QueryResultRow>(
  text: string,
  params: readonly unknown[] = [],
): Promise<T[]> {
  const result = await getPool().query<T>(text, params as unknown[]);
  return result.rows;
}

/**
 * Runs `fn` inside a transaction, committing on success and rolling back on any
 * error.
 *
 * Saving a scan writes to four tables and updates finding lifecycle state. A
 * failure halfway through would leave a scan row with no findings, or findings
 * marked resolved by a scan that was never fully recorded — and the lifecycle
 * dates, once wrong, are not recoverable by re-running anything. Either all of
 * it lands or none of it does.
 *
 * The client is always released, including on failure, because a leaked client
 * silently shrinks the pool until the next operation blocks forever waiting for
 * one that is never coming back.
 *
 * @param fn - receives a dedicated client; every query inside must use it
 *   rather than the pool, or that query runs outside the transaction.
 * @returns whatever `fn` returns.
 * @throws whatever `fn` throws, after rolling back.
 */
export async function withTransaction<T>(
  fn: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await getPool().connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    // A rollback can itself fail if the connection died mid-transaction. That
    // must not mask the original error, which is the one that explains what
    // actually went wrong.
    try {
      await client.query("ROLLBACK");
    } catch {
      // Intentionally swallowed; the original error is rethrown below.
    }
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Checks that the database is reachable and answers queries.
 *
 * Called by the CLIs before doing real work, so an unreachable container
 * produces one clear sentence instead of a driver stack trace.
 *
 * @throws an error naming the connection (without credentials) and the likely
 *   fix.
 */
export async function assertDatabaseReachable(): Promise<void> {
  const config = databaseConfig();
  try {
    await query("SELECT 1");
  } catch (error) {
    throw new Error(
      `Cannot reach the database at ${describeConnection(config)}: ` +
        `${error instanceof Error ? error.message : String(error)}\n` +
        "Is it running? Start it with `docker compose up -d db`.",
    );
  }
}
