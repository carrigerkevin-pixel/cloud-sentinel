/**
 * CloudSentinel — database management CLI.
 *
 * Applies migrations and reports schema state.
 *
 *   npm run db:migrate     apply every pending migration
 *   npm run db:status      show what is applied, pending, or modified
 *
 * Where it sits in the architecture: setup, alongside `npm run seed`. It is run
 * once after starting the database container, and again whenever a migration is
 * added. Nothing in the scan path depends on it at runtime.
 *
 *   docker compose up -d db  -->  npm run db:migrate  -->  npm run scan -- --save
 *
 * SECURITY: connection settings come from the environment via
 * lib/db/client.ts, which refuses non-loopback hosts unless explicitly
 * permitted. No credential is printed by any output path in this file — the
 * banner uses `describeConnection`, which renders user, host, port, and
 * database but never the password.
 *
 * Exit status:
 *
 *   0  the command succeeded
 *   1  the database was unreachable, or a migration failed
 *   2  bad arguments
 */

import {
  assertDatabaseReachable,
  closePool,
  databaseConfig,
  describeConnection,
} from "../lib/db/client.ts";
import { migrationStatus, runMigrations } from "../lib/db/migrate.ts";

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

/** ANSI codes, matching the palette the other CloudSentinel CLIs use. */
const style = {
  bold: (text: string) => `\x1b[1m${text}\x1b[0m`,
  dim: (text: string) => `\x1b[90m${text}\x1b[0m`,
  red: (text: string) => `\x1b[31m${text}\x1b[0m`,
  yellow: (text: string) => `\x1b[33m${text}\x1b[0m`,
  green: (text: string) => `\x1b[32m${text}\x1b[0m`,
};

function printUsage(): void {
  console.log(
    "\nUsage: npm run db:<command>\n\n" +
      "  db:migrate    apply every pending migration\n" +
      "  db:status     show applied, pending, and modified migrations\n\n" +
      "Start the database first with: docker compose up -d db\n",
  );
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/** Applies pending migrations, printing each as it lands. */
async function migrate(): Promise<void> {
  const applied = await runMigrations((migration) => {
    console.log(`  ${style.green("+")} ${migration.name}`);
  });

  if (applied.length === 0) {
    console.log(style.dim("  already up to date"));
    return;
  }
  console.log(
    `\n${style.bold(`Applied ${applied.length} migration(s).`)}\n`,
  );
}

/** Prints what is applied, what is pending, and anything that has been edited. */
async function status(): Promise<void> {
  const { applied, pending, modified } = await migrationStatus();

  console.log(`\n${style.bold(`Applied (${applied.length})`)}`);
  if (applied.length === 0) {
    console.log(style.dim("  none — run npm run db:migrate"));
  }
  for (const migration of applied) {
    console.log(
      `  ${style.green("✓")} ${migration.name} ` +
        style.dim(migration.applied_at.toISOString()),
    );
  }

  console.log(`\n${style.bold(`Pending (${pending.length})`)}`);
  if (pending.length === 0) {
    console.log(style.dim("  none"));
  }
  for (const migration of pending) {
    console.log(`  ${style.yellow("→")} ${migration.name}`);
  }

  // Printed last and in warning colour because it is the one state here that
  // means something is actually wrong: the schema in the database no longer
  // matches the SQL in the repository.
  if (modified.length > 0) {
    console.log(`\n${style.bold(style.yellow("Modified after apply"))}`);
    for (const entry of modified) {
      console.log(`  ${style.yellow("!")} ${entry.name}`);
    }
    console.log(
      style.dim(
        "\n  These files changed after they were applied, so the database and\n" +
          "  the repository disagree. Migrations are append-only: revert the\n" +
          "  edit and add a new numbered migration instead.",
      ),
    );
  }
  console.log("");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const command = process.argv[2];

  if (!command || command === "--help") {
    printUsage();
    // Missing command is a usage error; an explicit --help is not.
    if (!command) process.exitCode = 2;
    return;
  }

  if (command !== "migrate" && command !== "status") {
    console.error(`\n${style.red("Unknown command:")} ${command}`);
    printUsage();
    process.exitCode = 2;
    return;
  }

  const config = databaseConfig();
  console.log(
    `\nCloudSentinel database ${style.dim(describeConnection(config))}`,
  );

  // Fail fast with one clear sentence rather than a driver stack trace.
  await assertDatabaseReachable();

  if (command === "migrate") await migrate();
  else await status();
}

main()
  .catch((error: unknown) => {
    console.error(
      `\n${style.red("Failed:")} ${
        error instanceof Error ? error.message : String(error)
      }\n`,
    );
    process.exitCode = 1;
  })
  // Node keeps the process alive while the pool holds open sockets, so without
  // this the CLI prints its output and then appears to hang.
  .finally(closePool);
