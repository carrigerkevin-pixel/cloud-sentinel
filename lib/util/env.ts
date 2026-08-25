/**
 * CloudSentinel — `.env` file loading.
 *
 * A minimal loader that reads the project's `.env` into `process.env` so the
 * CLIs pick up local configuration without every command needing the variables
 * exported in the shell first.
 *
 * Where it sits in the architecture: a leaf utility. lib/db/client.ts calls it
 * before reading connection settings; nothing else depends on it.
 *
 * Why this is hand-written rather than a `dotenv` dependency: the entire
 * requirement is "read KEY=VALUE lines from one file", which is the twenty
 * lines below. For a project whose stated purpose is following good security
 * practice, adding a package to the dependency tree — and therefore to the
 * supply chain — to avoid writing twenty lines is a poor trade. Fewer
 * dependencies is itself a security property.
 *
 * SECURITY: this reads credentials into process memory. Two rules follow from
 * that and are enforced below: values are never logged, and an existing
 * environment variable is never overwritten.
 */

import { readFileSync } from "node:fs";

/** Tracks whether the file has already been read, so repeated calls are free. */
let loaded = false;

/**
 * Loads `.env` into `process.env`, if the file exists.
 *
 * Variables already present in the environment win. That precedence is the
 * important part: CI and container environments inject configuration directly,
 * and a `.env` file that silently overrode them would mean a stray local file
 * could redirect a deployed process — the exact failure this ordering prevents.
 * It also makes one-off overrides work the way anyone would expect:
 *
 *     POSTGRES_PORT=5433 npm run db:migrate
 *
 * Parsing is deliberately simple, matching what `.env.example` documents:
 * `KEY=VALUE` one per line, `#` comments, blank lines ignored, and surrounding
 * quotes stripped from the value. It does not support multi-line values,
 * variable interpolation, or `export` prefixes. If a value ever needs those,
 * it belongs in a secret manager rather than in a file on disk.
 *
 * @param path - file to read. Defaults to `.env` in the current directory,
 *   which is the repository root for every npm script in this project.
 * @returns the names of the variables that were set — never their values, so
 *   this can be logged safely. Empty when the file is absent, which is a normal
 *   state and not an error: CI has no `.env` and does not need one.
 */
export function loadEnvFile(path = ".env"): string[] {
  if (loaded) return [];
  loaded = true;

  let contents: string;
  try {
    contents = readFileSync(path, "utf8");
  } catch {
    // A missing .env is expected in CI and in any environment that injects
    // configuration directly. Anything else wrong with the file (permissions,
    // encoding) is also not worth failing a scan over — the caller will produce
    // a specific error about the variable it actually needed.
    return [];
  }

  const applied: string[] = [];

  for (const rawLine of contents.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith("#")) continue;

    const separator = line.indexOf("=");
    if (separator <= 0) continue;

    const key = line.slice(0, separator).trim();
    let value = line.slice(separator + 1).trim();

    // Strip one layer of matching quotes, so a value containing spaces can be
    // written the way a shell would accept it.
    if (
      (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
      (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
    ) {
      value = value.slice(1, -1);
    }

    // The real environment always wins — see the note above.
    if (process.env[key] !== undefined) continue;

    process.env[key] = value;
    applied.push(key);
  }

  return applied;
}

/**
 * Resets the "already loaded" latch.
 *
 * Exists for tests, which need to load different fixture files in one process.
 * Not used by application code — calling it in a CLI would re-read the file for
 * no reason.
 */
export function resetEnvLoaderForTests(): void {
  loaded = false;
}
