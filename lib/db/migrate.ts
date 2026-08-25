/**
 * CloudSentinel — database migrations.
 *
 * Applies the numbered `.sql` files in `db/migrations/` in order, recording
 * each one so it is never applied twice. Driven by `npm run db:migrate` and
 * `npm run db:status` (scripts/db.ts).
 *
 * Where it sits in the architecture: setup, not runtime. Nothing in the scan
 * path calls this — the schema is expected to exist before a scan is saved.
 *
 *   db/migrations/*.sql --> [ migrate ] --> Postgres schema
 *
 * Why a migration runner rather than a single `schema.sql` that gets re-applied:
 * the moment there is real scan history in the database, "drop everything and
 * recreate it" stops being an acceptable way to change the schema. Migrations
 * make schema changes additive and ordered, so an existing database can be
 * brought forward without losing the first-seen dates that give findings their
 * value. It is also the shape every real project ends up needing, so building
 * the small version now avoids retrofitting one later around live data.
 *
 * Three properties this implementation deliberately has:
 *
 *   - **Each migration runs inside a transaction.** Postgres supports
 *     transactional DDL, which many databases do not. A migration that fails
 *     halfway leaves the schema exactly as it was, rather than half-applied
 *     with no record of how far it got — the state that requires manual repair.
 *   - **A checksum is stored for every applied file.** Editing an already-
 *     applied migration is caught immediately, instead of producing a database
 *     that silently disagrees with the SQL in the repository. That divergence
 *     is invisible until something fails for an unrelated-looking reason.
 *   - **Advisory lock around the whole run.** Two processes migrating at once
 *     would both see the same pending list and both try to apply it.
 */

import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

import type { PoolClient } from "pg";

import { getPool, query, withTransaction } from "./client.ts";

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/**
 * Where migration files live, resolved relative to this file rather than to the
 * process's working directory.
 *
 * `npm run db:migrate` always runs from the repository root, but a future
 * dashboard route or a test could call this from anywhere. Resolving from
 * `import.meta.dirname` means the runner finds its migrations regardless.
 */
const MIGRATIONS_DIR = join(import.meta.dirname, "..", "..", "db", "migrations");

/** One migration file on disk. */
export interface Migration {
  /** Numeric prefix, e.g. `1` for `0001_init.sql`. Determines apply order. */
  version: number;
  /** Full filename, used as the identity recorded in `schema_migrations`. */
  name: string;
  sql: string;
  /** SHA-256 of the file contents, for tamper detection. */
  checksum: string;
}

/**
 * Reads and orders every migration file.
 *
 * Ordering is by the parsed numeric prefix, not by filename string comparison.
 * That distinction matters at exactly the wrong moment: sorted as strings,
 * `0010_x.sql` sorts before `0009_x.sql`, so migration ten would run before
 * nine and fail against a table that does not exist yet. Parsing the number
 * makes the ordering mean what it looks like it means.
 *
 * @returns migrations in the order they must be applied.
 * @throws if a filename does not start with digits followed by an underscore,
 *   because a file the runner cannot order is a file it cannot safely apply.
 */
export function loadMigrations(): Migration[] {
  const files = readdirSync(MIGRATIONS_DIR).filter((file) =>
    file.endsWith(".sql"),
  );

  const migrations = files.map((name): Migration => {
    const match = /^(\d+)_/.exec(name);
    if (!match) {
      throw new Error(
        `Migration "${name}" does not start with a numeric prefix. ` +
          "Rename it to the form 0002_description.sql so its order is defined.",
      );
    }

    const sql = readFileSync(join(MIGRATIONS_DIR, name), "utf8");
    return {
      version: Number(match[1]),
      name,
      sql,
      // Normalising line endings before hashing keeps the checksum stable
      // across platforms. Without it, git's autocrlf turns every migration on
      // Windows into an apparent tamper the moment the repo is cloned on Linux.
      checksum: createHash("sha256")
        .update(sql.replace(/\r\n/g, "\n"))
        .digest("hex"),
    };
  });

  migrations.sort((a, b) => a.version - b.version);

  const duplicate = migrations.find(
    (migration, index) =>
      index > 0 && migration.version === migrations[index - 1]!.version,
  );
  if (duplicate) {
    throw new Error(
      `Two migrations share version ${duplicate.version}. Version numbers must ` +
        "be unique, or the order they apply in is undefined.",
    );
  }

  return migrations;
}

// ---------------------------------------------------------------------------
// Bookkeeping table
// ---------------------------------------------------------------------------

/**
 * Creates the ledger table the runner uses to know what it has already done.
 *
 * Written in code rather than as migration `0000` for the obvious bootstrap
 * reason: the runner cannot read the list of applied migrations from a table
 * that a migration was supposed to create. `IF NOT EXISTS` makes it safe on
 * every run.
 */
async function ensureMigrationsTable(): Promise<void> {
  await query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version     INTEGER PRIMARY KEY,
      name        TEXT NOT NULL,
      checksum    TEXT NOT NULL,
      applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
}

/** A migration that has already been applied, as recorded in the database. */
export interface AppliedMigration {
  version: number;
  name: string;
  checksum: string;
  applied_at: Date;
}

/** Reads the ledger, oldest first. */
export async function appliedMigrations(): Promise<AppliedMigration[]> {
  await ensureMigrationsTable();
  return query<AppliedMigration>(
    "SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version",
  );
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/** What `npm run db:status` reports. */
export interface MigrationStatus {
  applied: AppliedMigration[];
  pending: Migration[];
  /** Applied migrations whose file on disk no longer matches what was applied. */
  modified: Array<{ name: string; expected: string; actual: string }>;
}

/**
 * Compares the migrations on disk with the ones recorded in the database.
 *
 * The `modified` list is the interesting output. An applied migration whose
 * file has since been edited means the database and the repository have
 * diverged: the schema in Postgres reflects the *old* text, while anyone
 * reading the repository sees the new one. Detecting it here turns a subtle,
 * long-lived inconsistency into an immediate, specific error.
 */
export async function migrationStatus(): Promise<MigrationStatus> {
  const onDisk = loadMigrations();
  const applied = await appliedMigrations();
  const appliedByVersion = new Map(applied.map((row) => [row.version, row]));

  const modified: MigrationStatus["modified"] = [];
  for (const migration of onDisk) {
    const record = appliedByVersion.get(migration.version);
    if (record && record.checksum !== migration.checksum) {
      modified.push({
        name: migration.name,
        expected: record.checksum,
        actual: migration.checksum,
      });
    }
  }

  return {
    applied,
    pending: onDisk.filter(
      (migration) => !appliedByVersion.has(migration.version),
    ),
    modified,
  };
}

// ---------------------------------------------------------------------------
// Applying
// ---------------------------------------------------------------------------

/**
 * Arbitrary constant identifying CloudSentinel's migration lock.
 *
 * Postgres advisory locks are keyed by a number chosen by the application; any
 * value works as long as everything that migrates this database agrees on it.
 */
const MIGRATION_LOCK_ID = 4712025;

/**
 * Applies every pending migration, in order.
 *
 * Each migration runs in its own transaction, so a failure leaves the
 * migrations before it applied and the failing one entirely rolled back —
 * including its ledger row, which is written inside the same transaction. That
 * is what makes a failed migration safe to fix and re-run: there is never a
 * half-applied file, and never a ledger entry for one that did not finish.
 *
 * @param onApplied - called after each successful migration, for CLI progress.
 * @returns the migrations that were applied, in order. Empty when up to date.
 * @throws if any migration file has been edited since it was applied, before
 *   applying anything at all.
 */
export async function runMigrations(
  onApplied: (migration: Migration) => void = () => {},
): Promise<Migration[]> {
  await ensureMigrationsTable();

  // Serialises concurrent runners. Taken on a dedicated client because an
  // advisory lock belongs to the session that took it — acquiring it on a
  // pooled connection that is then returned would release it early.
  const lockClient = await getPool().connect();
  try {
    await lockClient.query("SELECT pg_advisory_lock($1)", [MIGRATION_LOCK_ID]);

    const status = await migrationStatus();

    // Checked before applying anything. Refusing to proceed is the right
    // response: the runner cannot know whether the edit was meant to change the
    // schema (in which case it needs a new migration) or was an accident, and
    // guessing either way makes the divergence worse.
    if (status.modified.length > 0) {
      const names = status.modified.map((entry) => entry.name).join(", ");
      throw new Error(
        `Already-applied migration(s) have been modified: ${names}. ` +
          "Migrations are append-only — revert the change and add a new " +
          "numbered migration instead. If this database is disposable, reset " +
          "it with `docker compose down -v`.",
      );
    }

    const applied: Migration[] = [];
    for (const migration of status.pending) {
      await withTransaction(async (client: PoolClient) => {
        // The file may contain many statements; node-postgres sends the whole
        // string in one simple-query message, which Postgres executes as a
        // batch inside the surrounding transaction.
        await client.query(migration.sql);
        await client.query(
          "INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)",
          [migration.version, migration.name, migration.checksum],
        );
      });
      applied.push(migration);
      onApplied(migration);
    }

    return applied;
  } finally {
    // Released even on failure, or the next run blocks forever waiting for a
    // lock held by a process that has already exited.
    await lockClient.query("SELECT pg_advisory_unlock($1)", [
      MIGRATION_LOCK_ID,
    ]);
    lockClient.release();
  }
}
