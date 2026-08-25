/**
 * CloudSentinel — rule engine entry point.
 *
 * Runs every registered compliance rule over an inventory and prints the
 * findings. This is the command that answers the question the whole project
 * exists to answer: what is wrong with this environment?
 *
 *   npm run scan                              collect live, then evaluate
 *   npm run scan -- --input <file>            evaluate a saved inventory
 *   npm run scan -- --json                    full scan result as JSON
 *   npm run scan -- --out <file>              write the scan result to a file
 *   npm run scan -- --severity high           show only high and critical
 *   npm run scan -- --fail-on critical        exit non-zero if any critical
 *   npm run scan -- --rules                   list the registered rules
 *   npm run scan -- --save                    store the scan in Postgres
 *
 * The `--input` form needs no LocalStack, no Docker, and no credentials:
 *
 *   npm run scan -- --input fixtures/inventory.json
 *
 * Where it sits in the architecture: the far end of stage two. It owns no
 * security logic of its own — the rules decide what is wrong (lib/rules/) and
 * the engine decides how to record it (lib/rules/engine.ts). Everything here is
 * argument parsing, presentation, and exit status.
 *
 *   LocalStack ─┐
 *               ├─> ResourceInventory --> [ runRules ] --> ScanResult --> stdout
 *   --input ────┘
 *
 * SECURITY: read-only. When collecting live it goes through the same
 * `List*`/`Get*`/`Describe*`-only collectors as `npm run collect`, and
 * lib/aws/localstack.ts refuses to build a client for any endpoint that is not
 * loopback. Nothing in the scan path can change the environment it audits.
 *
 * Exit status, which is what makes this usable as a CI gate:
 *
 *   0  the scan ran and nothing tripped the `--fail-on` threshold
 *   1  a finding at or above the threshold, or the inventory had collection
 *      errors — a scan that could not see everything must not report success
 *   2  bad arguments
 *
 * Without `--fail-on`, findings alone do not fail the command. That default is
 * deliberate: during development every run would otherwise exit non-zero and
 * the signal would stop meaning anything. CI is expected to pass the flag
 * explicitly and choose its own threshold.
 */

import { readFile, writeFile } from "node:fs/promises";

import { collectInventory } from "../lib/collectors/inventory.ts";
import {
  closePool,
  databaseConfig,
  describeConnection,
} from "../lib/db/client.ts";
import { describeLifecycle } from "../lib/db/lifecycle.ts";
import { saveScan } from "../lib/db/scans.ts";
import {
  ALL_RULES,
  countBySeverity,
  hasFindingAtOrAbove,
  runRules,
} from "../lib/rules/engine.ts";
import { SEVERITY_ORDER } from "../lib/rules/types.ts";
import type { Finding, ScanResult, Severity } from "../lib/rules/types.ts";
import type { ResourceInventory } from "../lib/types/resource.ts";

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

/** ANSI codes, matching the palette used by the seed and collect scripts. */
const style = {
  bold: (text: string) => `\x1b[1m${text}\x1b[0m`,
  dim: (text: string) => `\x1b[90m${text}\x1b[0m`,
  red: (text: string) => `\x1b[31m${text}\x1b[0m`,
  yellow: (text: string) => `\x1b[33m${text}\x1b[0m`,
  green: (text: string) => `\x1b[32m${text}\x1b[0m`,
  magenta: (text: string) => `\x1b[35m${text}\x1b[0m`,
  cyan: (text: string) => `\x1b[36m${text}\x1b[0m`,
};

/**
 * Colour and label for each severity.
 *
 * Fixed-width labels so the finding lines form readable columns in a terminal;
 * colour is a second channel on top of the text rather than the only one, since
 * output is frequently piped somewhere that strips it.
 */
const SEVERITY_STYLE: Record<Severity, { label: string; paint: (t: string) => string }> = {
  critical: { label: "CRITICAL", paint: style.red },
  high: { label: "HIGH    ", paint: style.magenta },
  medium: { label: "MEDIUM  ", paint: style.yellow },
  low: { label: "LOW     ", paint: style.cyan },
};

/**
 * Wraps text to a width, indenting continuation lines.
 *
 * Finding details quote real policy statements, which are long. Left unwrapped
 * they turn the report into a wall that nobody reads to the end of — and the
 * evidence is the part that makes a finding actionable, so it has to survive
 * contact with an 80-column terminal.
 */
function wrap(text: string, width: number, indent: string): string {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let current = "";

  for (const word of words) {
    if (current.length === 0) {
      current = word;
    } else if (current.length + 1 + word.length <= width) {
      current += ` ${word}`;
    } else {
      lines.push(current);
      current = word;
    }
  }
  if (current.length > 0) lines.push(current);

  return lines.join(`\n${indent}`);
}

/** Prints one finding as a headline plus indented evidence and remediation. */
function printFinding(finding: Finding): void {
  const { label, paint } = SEVERITY_STYLE[finding.severity];

  // Inconclusive results are marked in the headline rather than being sorted
  // to the bottom. "We could not check whether this bucket is public" needs to
  // sit next to the public-bucket findings, because a gap in coverage on a
  // critical check is itself a critical problem.
  const marker =
    finding.status === "inconclusive" ? style.yellow(" [inconclusive]") : "";

  console.log(
    `\n  ${paint(label)}  ${style.bold(finding.title)}${marker}\n` +
      `            ${style.dim(`${finding.resourceType} ${finding.resourceName}`)}`,
  );
  console.log(`            ${wrap(finding.detail, 66, "            ")}`);
  console.log(
    `            ${style.dim(`Fix: ${wrap(finding.remediation, 66, "            ")}`)}`,
  );
  console.log(
    `            ${style.dim(`${finding.benchmark}  ·  rule ${finding.ruleId}`)}`,
  );
}

/** Prints the whole scan result as a human-readable report. */
function printReport(result: ScanResult, shown: Finding[]): void {
  const counts = countBySeverity(result.findings);

  console.log(
    `\n${style.bold("CloudSentinel scan")} ${style.dim(
      `${result.endpoint} (${result.region})`,
    )}\n` +
      `${style.dim(`collected ${result.collectedAt}`)}`,
  );

  if (shown.length === 0) {
    console.log(`\n${style.green("  No findings.")}`);
  } else {
    for (const finding of shown) printFinding(finding);
  }

  // The severity breakdown counts *every* finding, not just the ones displayed,
  // so a `--severity` filter can never make the environment look cleaner than
  // it is. Hiding findings from the list is a display choice; hiding them from
  // the totals would be a lie.
  console.log(
    `\n${style.bold("Summary")}\n` +
      `  ${style.red(`critical ${counts.critical}`)}  ` +
      `${style.magenta(`high ${counts.high}`)}  ` +
      `${style.yellow(`medium ${counts.medium}`)}  ` +
      `${style.cyan(`low ${counts.low}`)}\n` +
      `  ${result.findings.length} findings across ` +
      `${result.resourcesScanned - result.resourcesClean} of ` +
      `${result.resourcesScanned} resources ` +
      `${style.dim(`(${result.resourcesClean} clean)`)}\n` +
      `  ${style.bold(`risk score ${result.riskScore}/100`)}`,
  );

  const inconclusive = result.findings.filter(
    (finding) => finding.status === "inconclusive",
  ).length;
  if (inconclusive > 0) {
    console.log(
      style.yellow(
        `  ${inconclusive} check(s) could not be completed — treat those ` +
          "resources as unverified, not as compliant.",
      ),
    );
  }

  if (result.collectionErrors > 0) {
    console.log(
      style.yellow(
        `  ${result.collectionErrors} collection error(s) in the underlying ` +
          "inventory: this scan did not see the whole environment.",
      ),
    );
  }

  if (shown.length !== result.findings.length) {
    console.log(
      style.dim(
        `  (${result.findings.length - shown.length} finding(s) hidden by the ` +
          "--severity filter)",
      ),
    );
  }
  console.log("");
}

/** Prints the registered rules, for `--rules`. */
function printRules(): void {
  console.log(`\n${style.bold(`Registered rules (${ALL_RULES.length})`)}\n`);
  for (const rule of ALL_RULES) {
    const { label, paint } = SEVERITY_STYLE[rule.severity];
    console.log(`  ${paint(label)}  ${style.bold(rule.id)}  ${style.dim(rule.appliesTo)}`);
    console.log(`            ${rule.title}`);
    console.log(`            ${style.dim(rule.benchmark)}\n`);
  }
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

/** Everything the CLI accepts, after parsing. */
interface Options {
  inputPath: string | null;
  outPath: string | null;
  asJson: boolean;
  minSeverity: Severity | null;
  failOn: Severity | null;
  listRules: boolean;
  /** Persist this scan to Postgres, updating finding lifecycle. */
  save: boolean;
}

function printUsage(): void {
  console.log(
    "\nUsage: npm run scan [-- <options>]\n\n" +
      "  --input <file>       evaluate a saved inventory instead of collecting live\n" +
      "  --json               print the full scan result as JSON (no report)\n" +
      "  --out <file>         write the scan result JSON to <file>\n" +
      "  --severity <level>   only display findings at or above this level\n" +
      "  --fail-on <level>    exit 1 if any finding is at or above this level\n" +
      "  --rules              list the registered rules and exit\n" +
      "  --save               store the scan in Postgres and update finding\n" +
      "                       lifecycle (needs docker compose up -d db)\n" +
      "  --help               show this message\n\n" +
      `  <level> is one of: ${SEVERITY_ORDER.join(", ")}\n`,
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

/** Validates a severity argument, listing the valid values when it is wrong. */
function parseSeverity(value: string, flag: string): Severity {
  if ((SEVERITY_ORDER as readonly string[]).includes(value)) {
    return value as Severity;
  }
  throw new UsageError(
    `${flag} must be one of: ${SEVERITY_ORDER.join(", ")} (got "${value}")`,
  );
}

/**
 * A bad-arguments error, distinguished from a runtime failure so the two can
 * exit with different codes — 2 for "you typed it wrong", 1 for "the scan
 * found something or could not run". A CI job needs to tell those apart.
 */
class UsageError extends Error {}

function parseArgs(args: string[]): Options {
  return {
    inputPath: args.includes("--input") ? valueFor(args, "--input") : null,
    outPath: args.includes("--out") ? valueFor(args, "--out") : null,
    asJson: args.includes("--json"),
    minSeverity: args.includes("--severity")
      ? parseSeverity(valueFor(args, "--severity"), "--severity")
      : null,
    failOn: args.includes("--fail-on")
      ? parseSeverity(valueFor(args, "--fail-on"), "--fail-on")
      : null,
    listRules: args.includes("--rules"),
    save: args.includes("--save"),
  };
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Loads an inventory from disk.
 *
 * The parsed JSON is trusted to match {@link ResourceInventory} rather than
 * being validated field by field. That is acceptable because the only producer
 * is `npm run collect` and the only consumers are this project's own rules,
 * which are written to tolerate missing data. If inventories ever arrive from
 * somewhere less trusted, this is the boundary where schema validation belongs.
 */
async function loadInventory(path: string): Promise<ResourceInventory> {
  try {
    return JSON.parse(await readFile(path, "utf8")) as ResourceInventory;
  } catch (error) {
    throw new Error(
      `Could not read inventory from ${path}: ` +
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

  if (options.listRules) {
    printRules();
    return;
  }

  // Progress goes to stderr, never stdout, so `--json` output stays a clean
  // stream that can be piped into jq or redirected to a file.
  if (!options.asJson) {
    console.error(
      options.inputPath
        ? `CloudSentinel scan <- ${options.inputPath}`
        : "CloudSentinel scan <- live collection",
    );
  }

  const inventory = options.inputPath
    ? await loadInventory(options.inputPath)
    : await collectInventory();

  const result = runRules(inventory);

  // Saving happens before the report is printed, so that a database failure
  // surfaces as an error rather than appearing after a screenful of findings
  // that look like a completed run.
  if (options.save) {
    const config = databaseConfig();
    const saved = await saveScan(inventory, result);

    // Progress goes to stderr so `--json` stdout stays a clean stream.
    const message =
      `Saved scan #${saved.scanId} to ${describeConnection(config)} — ` +
      describeLifecycle(saved.plan);
    if (options.asJson) console.error(message);
    else console.error(style.green(message));

    // `unverified` findings are ones a previous scan reported that this scan
    // could not re-check. They are not resolved and not re-reported, so without
    // this line they would silently vanish from the run's output entirely.
    if (saved.plan.unverified.length > 0) {
      console.error(
        style.yellow(
          `  ${saved.plan.unverified.length} previously-open finding(s) could ` +
            "not be re-checked by this scan and remain open.",
        ),
      );
    }
  }

  if (options.outPath) {
    await writeFile(options.outPath, `${JSON.stringify(result, null, 2)}\n`, "utf8");
    if (!options.asJson) console.error(style.green(`Wrote ${options.outPath}`));
  }

  if (options.asJson) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    const shown =
      options.minSeverity === null
        ? result.findings
        : result.findings.filter(
            (finding) =>
              SEVERITY_ORDER.indexOf(finding.severity) <=
              SEVERITY_ORDER.indexOf(options.minSeverity!),
          );
    printReport(result, shown);
  }

  // A partial scan is not a successful scan, regardless of the threshold: the
  // findings it did produce came from an incomplete picture.
  if (result.collectionErrors > 0) {
    process.exitCode = 1;
    return;
  }

  if (options.failOn && hasFindingAtOrAbove(result.findings, options.failOn)) {
    process.exitCode = 1;
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
    console.error(
      `\n${style.red("Failed:")} ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
    process.exitCode = 1;
  })
  // Without `--save` no pool is ever created and this is a no-op. With it, Node
  // would otherwise keep the process alive on the pool's open sockets and the
  // command would appear to hang after printing its report.
  .finally(closePool);
