/**
 * CloudSentinel — Python ML layer launcher.
 *
 * A thin bridge so the Python anomaly layer runs through the same `npm run`
 * interface as everything else in the project.
 *
 *   npm run ml:setup       create ml/.venv and install ml/requirements.txt
 *   npm run ml:features    extract behavioural features and print a summary
 *   npm run ml:detect      run both detectors, write fixtures/anomalies.json
 *   npm run ml:evaluate    compare the detections against the answer key
 *   npm run ml:pipeline    logs:gen -> detect -> evaluate, end to end
 *
 * Where it sits in the architecture: pure plumbing. It contains no analysis of
 * any kind — every decision lives in ml/*.py — and its only job is finding the
 * right Python interpreter and forwarding arguments to it.
 *
 * ---------------------------------------------------------------------------
 * Why this file exists at all
 * ---------------------------------------------------------------------------
 *
 * Two problems, both of which would otherwise land on whoever runs the project.
 *
 * First, **the virtual environment lives in a different place on every OS**.
 * Python puts its executables in `.venv/Scripts/python.exe` on Windows and
 * `.venv/bin/python` everywhere else. This project is developed on Windows and
 * its CI runs on Ubuntu, so a hard-coded path in package.json would work in
 * exactly one of those two places. The lookup below tries both.
 *
 * Second, **`npm run` is the one interface worth remembering**. Every other
 * stage of this project is an npm script; making the ML layer the sole
 * exception — "activate a venv first, then run python with the right working
 * directory" — is the kind of inconsistency that turns into a wrong command in
 * a README and a confused reader six months later.
 *
 * SECURITY: this spawns a Python interpreter with a fixed argument list and
 * `shell: false`, so no argument can be interpreted as shell syntax. The script
 * name is chosen from a hard-coded allowlist rather than taken from the command
 * line — without that, `npm run ml -- ../../something.py` would execute an
 * arbitrary file. User arguments are forwarded to Python as argv entries, which
 * Python's `argparse` validates; they never reach a shell.
 *
 * Exit status: whatever Python exited with, so a failing model or a failed
 * recall gate propagates out to CI. Exit 2 for a bad script name, and exit 1
 * with an actionable message if the virtual environment is missing.
 */

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** Where the virtual environment lives, relative to the repository root. */
const VENV_DIR = join("ml", ".venv");

/**
 * The Python entry points this launcher is allowed to run.
 *
 * An allowlist rather than passing the argument straight through. The value
 * arrives from the command line, and interpolating it into a path would let any
 * file on the machine be executed by this script — a needless hole in a tool
 * whose whole subject is least privilege.
 */
const SCRIPTS = {
  features: "ml/features.py",
  detect: "ml/detect.py",
  evaluate: "ml/evaluate.py",
} as const;

type ScriptName = keyof typeof SCRIPTS;

/** Terminal colours, matching the other scripts in this directory. */
const style = {
  bold: (text: string) => `\x1b[1m${text}\x1b[0m`,
  dim: (text: string) => `\x1b[90m${text}\x1b[0m`,
  red: (text: string) => `\x1b[31m${text}\x1b[0m`,
  green: (text: string) => `\x1b[32m${text}\x1b[0m`,
};

// ---------------------------------------------------------------------------
// Finding Python
// ---------------------------------------------------------------------------

/**
 * Locates the virtual environment's Python interpreter.
 *
 * @returns the path to the interpreter, or `null` if the venv does not exist.
 */
function venvPython(): string | null {
  const candidates = [
    // Windows.
    join(VENV_DIR, "Scripts", "python.exe"),
    // Linux, macOS, and the CI runner.
    join(VENV_DIR, "bin", "python"),
  ];

  return candidates.find((candidate) => existsSync(candidate)) ?? null;
}

/**
 * Picks the interpreter used to *create* the virtual environment.
 *
 * Deliberately not the same lookup as {@link venvPython}: at setup time there is
 * no venv yet, so this has to be a system Python. `python3` is tried first
 * because on Linux and macOS a bare `python` may be absent or may still be
 * Python 2; on Windows `python` is the normal spelling and `python3` is often a
 * Microsoft Store stub, so the fallback matters in both directions.
 *
 * @returns a list of interpreter names to try, in order.
 */
function systemPythonCandidates(): string[] {
  return process.platform === "win32"
    ? ["python", "python3", "py"]
    : ["python3", "python"];
}

// ---------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------

/**
 * Runs a command and resolves with its exit code.
 *
 * `shell: false` (the default) is load-bearing: arguments reach the child as an
 * argv array, so nothing in them can be parsed as a pipe, a redirect, or a
 * command separator. `stdio: "inherit"` lets the Python output stream straight
 * to the terminal as it is produced, rather than arriving in one block when the
 * process exits.
 *
 * @param command - executable to run.
 * @param args - arguments, passed as argv entries.
 * @param env - extra environment variables to add.
 * @returns the child's exit code, or 1 if it was killed by a signal.
 */
function run(
  command: string,
  args: string[],
  env: Record<string, string> = {},
): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: "inherit",
      env: { ...process.env, ...env },
    });

    child.on("error", reject);
    child.on("close", (code) => resolve(code ?? 1));
  });
}

/**
 * Creates the virtual environment and installs the requirements into it.
 *
 * @returns the exit code of the last step to run.
 */
async function setup(): Promise<number> {
  console.error(`${style.bold("Setting up the ML environment")}`);
  console.error(style.dim(`  ${VENV_DIR} <- ml/requirements.txt\n`));

  let created = venvPython();

  if (created === null) {
    let lastError: unknown = null;

    for (const candidate of systemPythonCandidates()) {
      try {
        console.error(style.dim(`  creating the venv with ${candidate}...`));
        const code = await run(candidate, ["-m", "venv", VENV_DIR]);
        if (code === 0) break;
      } catch (error) {
        // ENOENT just means this spelling of Python is not on PATH; try the
        // next one before giving up.
        lastError = error;
      }
    }

    created = venvPython();

    if (created === null) {
      console.error(
        `\n${style.red("Failed:")} could not create a virtual environment at ${VENV_DIR}.\n` +
          `Tried: ${systemPythonCandidates().join(", ")}\n` +
          "Install Python 3.11 or newer and make sure it is on PATH." +
          (lastError instanceof Error ? `\n(${lastError.message})` : ""),
      );
      return 1;
    }
  }

  const code = await run(created, [
    "-m",
    "pip",
    "install",
    "--quiet",
    "--upgrade",
    "--requirement",
    "ml/requirements.txt",
  ]);

  if (code === 0) {
    console.error(`\n${style.green("Ready.")} Run ${style.bold("npm run ml:pipeline")}\n`);
  }

  return code;
}

/**
 * Runs one of the allowlisted Python entry points.
 *
 * @param name - which script, from {@link SCRIPTS}.
 * @param args - extra arguments forwarded to the script.
 * @returns the script's exit code.
 */
async function runScript(name: ScriptName, args: string[]): Promise<number> {
  const python = venvPython();

  if (python === null) {
    console.error(
      `\n${style.red("Failed:")} no Python environment at ${VENV_DIR}.\n` +
        `Create it first:  ${style.bold("npm run ml:setup")}\n`,
    );
    return 1;
  }

  return run(python, [SCRIPTS[name], ...args], {
    // The ml/ modules import each other by bare name (`from features import
    // ...`), which resolves against the script's own directory — but only when
    // Python is invoked with a path inside it. Setting PYTHONPATH explicitly
    // makes the imports work regardless of how the process was launched.
    PYTHONPATH: "ml",
    // Force UTF-8 on stdout. Windows consoles default to a legacy code page
    // (cp1252 on this machine), and Python raises UnicodeEncodeError rather
    // than substituting when it cannot encode a character — so a single stray
    // non-ASCII byte in a report would crash the run after the work was done.
    PYTHONIOENCODING: "utf-8",
  });
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

function printUsage(): void {
  console.log(
    "\nUsage: npm run ml:<command> [-- <options>]\n\n" +
      "  ml:setup       create ml/.venv and install the Python dependencies\n" +
      "  ml:features    extract behavioural features and print a summary\n" +
      "  ml:detect      run both detectors, write fixtures/anomalies.json\n" +
      "  ml:evaluate    score the detections against the ground-truth labels\n" +
      "  ml:pipeline    generate logs, detect, and evaluate in one go\n\n" +
      "  Options after `--` are forwarded to the underlying Python script,\n" +
      "  which documents them under --help. For example:\n\n" +
      "    npm run ml:detect -- --contamination 0.005\n" +
      "    npm run ml:evaluate -- --require-recall 0.6\n",
  );
}

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);

  if (command === undefined || command === "--help") {
    printUsage();
    return;
  }

  if (command === "setup") {
    process.exitCode = await setup();
    return;
  }

  if (!(command in SCRIPTS)) {
    console.error(
      `\n${style.red("Usage:")} unknown command "${command}". ` +
        `Expected one of: setup, ${Object.keys(SCRIPTS).join(", ")}`,
    );
    printUsage();
    process.exitCode = 2;
    return;
  }

  process.exitCode = await runScript(command as ScriptName, args);
}

main().catch((error: unknown) => {
  console.error(
    `\n${style.red("Failed:")} ${
      error instanceof Error ? error.message : String(error)
    }`,
  );
  process.exitCode = 1;
});
