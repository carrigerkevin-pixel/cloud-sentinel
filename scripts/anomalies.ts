/**
 * CloudSentinel — anomaly persistence CLI.
 *
 * Loads the detections written by `ml/detect.py`, validates them, and stores
 * them in Postgres so the dashboard can show them.
 *
 *   npm run ml:save                            store fixtures/anomalies.json
 *   npm run ml:save -- --input <file>          store a different detections file
 *   npm run ml:save -- --dry-run               validate only, write nothing
 *   npm run ml:runs                            list stored detection runs
 *
 * Where it sits in the architecture: the bridge from the Python layer's output
 * into the database. It owns no analysis and no schema knowledge — validation
 * lives in lib/anomalies/ingest.ts and the SQL lives in lib/db/anomalies.ts.
 *
 *   fixtures/anomalies.json --> [ this file ] --> Postgres --> app/(app)/anomalies
 *
 * Why this is a separate command rather than a `--save` flag on the detector,
 * which is how `npm run scan -- --save` works: the detector is Python and the
 * database layer is TypeScript. Giving `ml/detect.py` a `--save` flag would
 * mean a second database driver, a second copy of the connection and TLS rules
 * in lib/db/client.ts, and a second place where a credential could be
 * mishandled. Keeping all database access in one language means those rules are
 * written and reviewed once.
 *
 * SECURITY: the detections file is treated as untrusted input and fully
 * validated before anything reaches the database — see the header of
 * lib/anomalies/ingest.ts for why this boundary is checked when the inventory
 * loader deliberately is not. Database credentials come from the environment
 * via lib/db/client.ts and are never printed, including in error messages.
 *
 * Exit status:
 *
 *   0  the run was stored (or validated, with --dry-run)
 *   1  the file was unreadable, malformed, or the database rejected it
 *   2  bad arguments
 */

import {
  closePool,
  databaseConfig,
  describeConnection,
} from "../lib/db/client.ts";
import {
  AnomalyReportError,
  loadAnomalyReport,
} from "../lib/anomalies/ingest.ts";
import {
  recentAnomalyRuns,
  saveAnomalyReport,
} from "../lib/db/anomalies.ts";

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

/** Terminal colours, matching the other scripts in this directory. */
const style = {
  bold: (text: string) => `\x1b[1m${text}\x1b[0m`,
  dim: (text: string) => `\x1b[90m${text}\x1b[0m`,
  red: (text: string) => `\x1b[31m${text}\x1b[0m`,
  green: (text: string) => `\x1b[32m${text}\x1b[0m`,
  cyan: (text: string) => `\x1b[36m${text}\x1b[0m`,
};

/** Default detections file, matching `ml/detect.py`'s default output. */
const DEFAULT_INPUT = "fixtures/anomalies.json";

/**
 * A bad-arguments error, so "you typed it wrong" exits 2 and a genuine failure
 * exits 1. Matches scripts/scan.ts.
 */
class UsageError extends Error {}

function printUsage(): void {
  console.log(
    "\nUsage: npm run ml:save [-- <options>]\n\n" +
      `  --input <file>   detections to store (default ${DEFAULT_INPUT})\n` +
      "  --dry-run        validate the file and print a summary, write nothing\n" +
      "  --help           show this message\n\n" +
      "  npm run ml:runs  list the detection runs already stored\n",
  );
}

/** Reads the value following a flag, or throws a usage error naming the flag. */
function valueFor(args: string[], flag: string): string {
  const index = args.indexOf(flag);
  const value = args[index + 1];
  if (value === undefined || value.startsWith("--")) {
    throw new UsageError(`${flag} requires a value`);
  }
  return value;
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/**
 * Loads, validates, and optionally stores a detections file.
 *
 * @param args - command-line arguments after the subcommand.
 */
async function save(args: string[]): Promise<void> {
  const inputPath = args.includes("--input")
    ? valueFor(args, "--input")
    : DEFAULT_INPUT;
  const dryRun = args.includes("--dry-run");

  const report = await loadAnomalyReport(inputPath);
  const { metadata } = report;

  console.error(`\n${style.bold("Detection run")} ${style.dim(inputPath)}`);
  console.error(
    style.dim(
      `  log seed ${metadata.seed} | ${metadata.days} days | ` +
        `${metadata.eventCount.toLocaleString()} events | ` +
        `${metadata.windowCount.toLocaleString()} windows`,
    ),
  );
  console.error(
    style.dim(
      `  alert budget ${metadata.alertBudget} per model | ` +
        `primary model ${metadata.primaryModel}`,
    ),
  );

  // The count by model is the number worth showing at a glance: a window both
  // models flagged is a stronger signal than one only the forest isolated, and
  // the split is invisible in a bare total.
  const both = report.anomalies.filter((a) => a.flaggedBy.length === 2).length;
  console.error(
    `\n  ${report.anomalies.length} flagged windows ` +
      style.dim(`(${both} flagged by both models)`),
  );

  for (const anomaly of report.anomalies.slice(0, 5)) {
    const name = anomaly.principalArn.split("/").pop() ?? anomaly.principalArn;
    const reason = anomaly.evidence[0]?.feature ?? "combination of features";
    console.error(
      `    ${style.cyan(name.padEnd(30))} ${anomaly.windowStart.slice(0, 16).replace("T", " ")}  ` +
        style.dim(`${anomaly.eventCount} events, ${reason}`),
    );
  }
  if (report.anomalies.length > 5) {
    console.error(style.dim(`    ... and ${report.anomalies.length - 5} more`));
  }

  if (dryRun) {
    console.error(
      `\n${style.green("Valid.")} ${style.dim("Nothing written (--dry-run).")}\n`,
    );
    return;
  }

  console.error(
    style.dim(`\n  Connecting to ${describeConnection(databaseConfig())}`),
  );

  const saved = await saveAnomalyReport(report);

  console.error(
    `${style.green("Saved")} run #${saved.runId} ` +
      style.dim(`(${saved.anomalyCount} anomalies inserted)`),
  );

  // Re-running against the same file inserts nothing, because of the unique
  // constraint on (run_id, principal_arn, window_start). Saying so explicitly
  // avoids the reasonable worry that a repeated command silently doubled the
  // data.
  if (saved.anomalyCount < report.anomalies.length) {
    console.error(
      style.dim(
        `  ${report.anomalies.length - saved.anomalyCount} were already present in this run and were skipped.`,
      ),
    );
  }
  console.error("");
}

/**
 * Lists the detection runs already stored.
 */
async function listRuns(): Promise<void> {
  const runs = await recentAnomalyRuns();

  if (runs.length === 0) {
    console.error(
      `\n${style.dim("No detection runs stored yet. Run:")} ` +
        `${style.bold("npm run ml:pipeline")} ${style.dim("then")} ${style.bold("npm run ml:save")}\n`,
    );
    return;
  }

  console.error(`\n${style.bold("Detection runs")}\n`);
  console.error(
    style.dim(
      `  ${"#".padEnd(6)} ${"detected".padEnd(18)} ${"seed".padEnd(16)} ${"days".padStart(5)} ${"alerts".padStart(7)} ${"budget".padStart(7)}`,
    ),
  );

  for (const run of runs) {
    console.error(
      `  ${String(run.id).padEnd(6)} ` +
        `${run.detectedAt.toISOString().slice(0, 16).replace("T", " ").padEnd(18)} ` +
        `${run.logSeed.slice(0, 16).padEnd(16)} ` +
        `${String(run.logDays).padStart(5)} ` +
        `${String(run.anomalyCount).padStart(7)} ` +
        `${String(run.alertBudget).padStart(7)}`,
    );
  }
  console.error("");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);

  if (command === undefined || command === "--help" || args.includes("--help")) {
    printUsage();
    return;
  }

  switch (command) {
    case "save":
      await save(args);
      return;
    case "runs":
      await listRuns();
      return;
    default:
      throw new UsageError(`unknown command "${command}" (expected save or runs)`);
  }
}

main()
  .catch((error: unknown) => {
    if (error instanceof UsageError) {
      console.error(`\n${style.red("Usage:")} ${error.message}`);
      printUsage();
      process.exitCode = 2;
      return;
    }

    // A malformed detections file gets its own message, because the fix is
    // different from a database failure: regenerate the file, do not check the
    // connection.
    if (error instanceof AnomalyReportError) {
      console.error(`\n${style.red("Invalid detections file:")} ${error.message}\n`);
      process.exitCode = 1;
      return;
    }

    console.error(
      `\n${style.red("Failed:")} ${
        error instanceof Error ? error.message : String(error)
      }\n`,
    );
    process.exitCode = 1;
  })
  // Without this Node keeps the process alive on the pool's open sockets and
  // the command appears to hang after printing its report.
  .finally(closePool);
