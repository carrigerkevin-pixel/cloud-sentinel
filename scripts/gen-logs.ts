/**
 * CloudSentinel — synthetic activity log generator CLI.
 *
 * Writes a month of fabricated CloudTrail-style events, with labelled attacks
 * hidden inside them, for the ML anomaly layer to analyse.
 *
 *   npm run logs:gen                        30 days, default seed, attacks on
 *   npm run logs:gen -- --days 7            a shorter window
 *   npm run logs:gen -- --seed other-run    a different reproducible dataset
 *   npm run logs:gen -- --no-attacks        clean baseline only (see below)
 *   npm run logs:gen -- --out data/log.json write somewhere else
 *   npm run logs:gen -- --summary           print statistics, write nothing
 *
 * Where it sits in the architecture: the entry point to stage three. It owns no
 * generation logic of its own — that is all in lib/logs/generator.ts. Everything
 * here is argument parsing, file writing, and the summary report.
 *
 *   [ this file ] --> fixtures/cloudtrail.json --------> ml/features.py
 *                 \-> fixtures/cloudtrail-labels.json -> ml/evaluate.py
 *
 * ---------------------------------------------------------------------------
 * Why the output is generated rather than committed
 * ---------------------------------------------------------------------------
 *
 * `fixtures/inventory.json` from phase 2 *is* committed, and the contrast is
 * deliberate rather than inconsistent. That file is a snapshot of state that
 * cannot be reproduced without Docker, LocalStack, an auth token and a seeded
 * account — so committing it is what lets the rule engine be developed and
 * tested offline.
 *
 * This file needs none of that. Generation is pure computation, takes about a
 * fifth of a second, and is deterministic: the same seed produces byte-identical
 * output on any machine. Committing thirty-odd megabytes of JSON that any
 * checkout can rebuild in 200ms would bloat every clone and put an unreviewable
 * blob in the history of a repository whose whole point is being read by
 * someone evaluating the work. So the outputs are gitignored, and CI runs this
 * command before the ML steps.
 *
 * The rule that follows: **anything downstream must be able to regenerate its
 * own input**, which is why the seed and window are recorded in the metadata of
 * both output files.
 *
 * ---------------------------------------------------------------------------
 * The two output files
 * ---------------------------------------------------------------------------
 *
 * Events and labels are written separately, and that separation is load-bearing
 * rather than tidiness. The detector reads only the events file; the answer key
 * is opened by nothing until `ml/evaluate.py` runs, after detection is already
 * finished. Anomaly detection here is unsupervised, so a model that could see
 * the labels while training would learn to predict them and the resulting
 * accuracy figure would measure nothing at all. Two files is a structural
 * guarantee against that, which is worth considerably more than a comment
 * asking people not to peek.
 *
 * SECURITY: everything written is fabricated — a documentation-range account
 * id, RFC 5737 example IP addresses, invented principal names. Nothing here
 * touches AWS, LocalStack, the database, or the network. See the header of
 * lib/logs/generator.ts for why real CloudTrail must never be substituted
 * casually: a genuine trail records who did what from where, and is not
 * something to drop into a public repository.
 *
 * Exit status:
 *
 *   0  the log was generated (and written, unless --summary)
 *   1  a file could not be written
 *   2  bad arguments
 */

import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import {
  DEFAULT_PRINCIPALS,
  generateActivity,
  type GeneratedActivity,
} from "../lib/logs/generator.ts";

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

/**
 * Terminal colours, matching scripts/scan.ts.
 *
 * Raw escape codes rather than a dependency, for the same reason given in
 * lib/util/env.ts: a package in the tree is a supply-chain surface, and this is
 * seven lines.
 */
const style = {
  bold: (text: string) => `\x1b[1m${text}\x1b[0m`,
  dim: (text: string) => `\x1b[90m${text}\x1b[0m`,
  red: (text: string) => `\x1b[31m${text}\x1b[0m`,
  yellow: (text: string) => `\x1b[33m${text}\x1b[0m`,
  green: (text: string) => `\x1b[32m${text}\x1b[0m`,
  cyan: (text: string) => `\x1b[36m${text}\x1b[0m`,
};

/** Default path for the events file. */
const DEFAULT_OUT = "fixtures/cloudtrail.json";

/**
 * Derives the labels path from the events path.
 *
 * `fixtures/cloudtrail.json` becomes `fixtures/cloudtrail-labels.json`. Derived
 * rather than a second flag so the two files cannot drift apart — a run that
 * wrote events for one seed next to labels from another would produce an
 * evaluation that is wrong in a way nobody would think to check.
 *
 * @param outPath - the events path.
 * @returns the matching labels path.
 */
function labelsPathFor(outPath: string): string {
  return outPath.replace(/\.json$/, "") + "-labels.json";
}

/**
 * Prints a human-readable summary of what was generated.
 *
 * Written to stderr rather than stdout so that a future `--json` mode, or a
 * shell redirect, keeps stdout clean — the same convention scripts/scan.ts
 * follows for its progress output.
 *
 * @param generated - the log and labels to describe.
 */
function printSummary(generated: GeneratedActivity): void {
  const { log, labels } = generated;
  const { metadata } = log;

  const perPrincipal = new Map<string, number>();
  let errorCount = 0;

  for (const event of log.events) {
    const arn = event.userIdentity.arn;
    perPrincipal.set(arn, (perPrincipal.get(arn) ?? 0) + 1);
    if (event.errorCode) errorCount += 1;
  }

  console.error(`\n${style.bold("Synthetic activity log")}`);
  console.error(
    style.dim(
      `  seed ${metadata.seed} · ${metadata.days} days from ${metadata.startTime.slice(0, 10)} · ${metadata.eventCount.toLocaleString()} events`,
    ),
  );

  console.error(`\n${style.bold("Principals")}`);
  for (const profile of DEFAULT_PRINCIPALS) {
    const count = perPrincipal.get(profile.arn) ?? 0;
    const name = profile.arn.split("/").pop() ?? profile.arn;
    // The two control principals are called out explicitly. They are the ones
    // a reader should check the detector against first, because they are the
    // ones a naive model gets wrong.
    const isControl = profile.description.startsWith("CONTROL");
    const tag = isControl ? style.green(" [control]") : "";
    console.error(
      `  ${name.padEnd(32)} ${String(count).padStart(6)} events${tag}`,
    );
    console.error(style.dim(`    ${profile.description}`));
  }

  console.error(
    `\n  ${style.dim("failed calls:")} ${errorCount.toLocaleString()} ` +
      style.dim(
        `(${((100 * errorCount) / Math.max(1, log.events.length)).toFixed(2)}% — the background permission-error rate)`,
      ),
  );

  if (labels.labels.length === 0) {
    console.error(
      `\n${style.yellow("No attacks injected")} ${style.dim("(--no-attacks). This run measures false positives on ordinary traffic.")}`,
    );
    return;
  }

  console.error(`\n${style.bold("Injected attacks")} ${style.dim("(the answer key — the detector never sees this)")}`);
  for (const label of labels.labels) {
    const name = label.principalArn.split("/").pop() ?? label.principalArn;
    console.error(
      `  ${style.red(label.scenario.padEnd(22))} ${style.cyan(name.padEnd(18))} ${label.startTime.slice(0, 16).replace("T", " ")}Z  ${String(label.eventIds.length).padStart(4)} events`,
    );
    console.error(style.dim(`    ${label.description}`));
  }
}

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

/**
 * A bad-arguments error, distinguished from a runtime failure so the two exit
 * with different codes — 2 for "you typed it wrong", 1 for "it did not work".
 */
class UsageError extends Error {}

/** Parsed command-line options. */
interface Options {
  seed: string | null;
  days: number | null;
  startTime: string | null;
  outPath: string;
  injectAttacks: boolean;
  summaryOnly: boolean;
}

function printUsage(): void {
  console.log(
    "\nUsage: npm run logs:gen [-- <options>]\n\n" +
      "  --seed <string>      PRNG seed; the same seed reproduces the log exactly\n" +
      "  --days <n>           length of the generated window (default 30)\n" +
      "  --start <iso>        UTC start timestamp (default 2026-06-01T00:00:00.000Z)\n" +
      "  --out <file>         events path (default fixtures/cloudtrail.json);\n" +
      "                       labels are written alongside as <file>-labels.json\n" +
      "  --no-attacks         generate clean baseline traffic with no injections,\n" +
      "                       for measuring the detector's false-positive rate\n" +
      "  --summary            print the summary without writing any file\n" +
      "  --help               show this message\n",
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

/**
 * Validates the `--days` argument.
 *
 * Rejects anything below 1 or above 365. The upper bound is not arbitrary: a
 * year of activity is roughly half a gigabyte of JSON, which would be a
 * surprising thing for a mistyped flag to produce on somebody's laptop.
 */
function parseDays(value: string): number {
  const days = Number(value);
  if (!Number.isInteger(days) || days < 1 || days > 365) {
    throw new UsageError(`--days must be a whole number from 1 to 365 (got "${value}")`);
  }
  return days;
}

/** Validates the `--start` argument as a parseable timestamp. */
function parseStart(value: string): string {
  if (Number.isNaN(new Date(value).getTime())) {
    throw new UsageError(`--start must be an ISO 8601 timestamp (got "${value}")`);
  }
  return value;
}

function parseArgs(args: string[]): Options {
  return {
    seed: args.includes("--seed") ? valueFor(args, "--seed") : null,
    days: args.includes("--days") ? parseDays(valueFor(args, "--days")) : null,
    startTime: args.includes("--start") ? parseStart(valueFor(args, "--start")) : null,
    outPath: args.includes("--out") ? valueFor(args, "--out") : DEFAULT_OUT,
    injectAttacks: !args.includes("--no-attacks"),
    summaryOnly: args.includes("--summary"),
  };
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Writes a JSON file, creating its directory if needed.
 *
 * Two-space indentation rather than compact output. The file is large either
 * way, and an indented file can be opened, scrolled and understood by someone
 * checking what the generator actually produced — which is the point of a
 * project built to be read. Since the file is gitignored, the size cost buys
 * nothing back in diff noise.
 *
 * @param path - destination.
 * @param value - anything JSON-serialisable.
 * @throws {Error} naming the path if the write fails, since the underlying
 *   errno message alone does not say which of the two files was the problem.
 */
async function writeJson(path: string, value: unknown): Promise<void> {
  try {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, JSON.stringify(value, null, 2) + "\n", "utf8");
  } catch (error) {
    throw new Error(
      `Could not write ${path}: ` +
        (error instanceof Error ? error.message : String(error)),
    );
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes("--help")) {
    printUsage();
    return;
  }

  const options = parseArgs(args);

  const started = Date.now();
  const generated = generateActivity({
    ...(options.seed !== null ? { seed: options.seed } : {}),
    ...(options.days !== null ? { days: options.days } : {}),
    ...(options.startTime !== null ? { startTime: options.startTime } : {}),
    injectAttacks: options.injectAttacks,
  });
  const elapsed = Date.now() - started;

  printSummary(generated);

  if (options.summaryOnly) {
    console.error(
      `\n${style.dim(`Generated in ${elapsed}ms. Nothing written (--summary).`)}\n`,
    );
    return;
  }

  const labelsPath = labelsPathFor(options.outPath);

  await writeJson(options.outPath, generated.log);
  await writeJson(labelsPath, generated.labels);

  console.error(
    `\n${style.green("Wrote")} ${options.outPath} ${style.dim(`(${generated.log.events.length.toLocaleString()} events)`)}`,
  );
  console.error(
    `${style.green("Wrote")} ${labelsPath} ${style.dim(`(${generated.labels.labels.length} labels — not read by the detector)`)}`,
  );
  console.error(style.dim(`Generated in ${elapsed}ms.\n`));
}

main().catch((error: unknown) => {
  if (error instanceof UsageError) {
    console.error(`\n${style.red("Usage:")} ${error.message}`);
    printUsage();
    process.exitCode = 2;
    return;
  }
  console.error(
    `\n${style.red("Failed:")} ${
      error instanceof Error ? error.message : String(error)
    }`,
  );
  process.exitCode = 1;
});
