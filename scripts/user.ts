/**
 * CloudSentinel — dashboard account management CLI.
 *
 * Creates and manages the accounts that can log in to the dashboard.
 *
 *   npm run user:create -- <email> [--admin]   create an account
 *   npm run user:list                          list accounts
 *   npm run user:passwd -- <email>             change a password
 *   npm run user:revoke -- <email>             log a user out everywhere
 *   npm run user:delete -- <email>             delete an account
 *
 * Where it sits in the architecture: setup, alongside `npm run db:migrate`.
 * The dashboard has no sign-up page — deliberately, since a security tool that
 * lets strangers register themselves an account is not one worth running — so
 * this CLI is the only way an account comes into existence.
 *
 *   docker compose up -d db --> npm run db:migrate --> npm run user:create
 *                                                            |
 *                                                            +--> npm run dev
 *
 * ## SECURITY: why the password is prompted for and never passed as an argument
 *
 * There is no `--password` flag, and adding one would be a mistake. A command
 * line argument is visible to every other process on the machine through the
 * process list, and it is written verbatim into the shell's history file, where
 * it survives long after the terminal is closed. An environment variable is
 * only slightly better: it is inherited by every child process.
 *
 * So the password is read from the terminal with echo suppressed, held in
 * memory only long enough to be hashed by lib/auth/password.ts, and never
 * written anywhere in plaintext.
 *
 * Exit status:
 *
 *   0  the command succeeded
 *   1  the database was unreachable, or the command failed
 *   2  bad arguments
 */

import { createInterface } from "node:readline";

import {
  assertDatabaseReachable,
  closePool,
  databaseConfig,
  describeConnection,
} from "../lib/db/client.ts";
import {
  createUser,
  deleteUser,
  DuplicateUserError,
  findUserByEmail,
  listUsers,
  MIN_PASSWORD_LENGTH,
  revokeSessions,
  setPassword,
} from "../lib/db/users.ts";

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
    "\nUsage: npm run user:<command>\n\n" +
      "  user:create -- <email> [--admin]   create an account (viewer unless --admin)\n" +
      "  user:list                          list accounts\n" +
      "  user:passwd -- <email>             change a password\n" +
      "  user:revoke -- <email>             invalidate every session for a user\n" +
      "  user:delete -- <email>             delete an account\n\n" +
      "The password is always prompted for, never passed as an argument —\n" +
      "arguments end up in the shell history and the process list.\n",
  );
}

// ---------------------------------------------------------------------------
// Reading a password from the terminal
// ---------------------------------------------------------------------------

/**
 * Prompts for a password without echoing it to the screen.
 *
 * Node's readline has no built-in hidden-input mode, so the standard approach
 * is used: override the interface's internal `_writeToOutput` so that
 * everything typed after the prompt is swallowed rather than printed. Without
 * this the password appears in the terminal, stays in the scrollback, and ends
 * up in any recording or screen share.
 *
 * The trailing newline is written manually, because suppressing the echo also
 * suppresses the one the terminal would normally emit on Enter.
 *
 * @param prompt - the text shown before the hidden input.
 * @returns what was typed, with no trailing newline.
 */
function promptHidden(prompt: string): Promise<string> {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: true,
  });

  // The cast reaches a documented-but-untyped internal. Isolated to this one
  // line so the rest of the file stays honest about its types.
  (rl as unknown as { _writeToOutput: (text: string) => void })._writeToOutput =
    function writeMasked(text: string) {
      // The prompt itself must still be printed; only the typed characters are
      // suppressed. readline re-emits the whole line on each keystroke, so
      // anything containing the prompt is a redraw and anything else is input.
      if (text.includes(prompt)) process.stdout.write(prompt);
    };

  return new Promise((resolve) => {
    rl.question(prompt, (answer) => {
      process.stdout.write("\n");
      rl.close();
      resolve(answer);
    });
  });
}

/**
 * Prompts for a new password twice and checks the two agree.
 *
 * The confirmation matters more than usual here, because the input is invisible
 * as it is typed and the value is immediately one-way hashed. A typo would
 * otherwise create an account whose password nobody knows, discoverable only at
 * the next failed login.
 *
 * @returns the password, or `null` if the two entries differed or it was too
 *   short. The caller reports and exits; nothing is written in either case.
 */
async function promptNewPassword(): Promise<string | null> {
  const password = await promptHidden("Password: ");

  if (password.length < MIN_PASSWORD_LENGTH) {
    console.error(
      `\n${style.red("Too short:")} passwords must be at least ` +
        `${MIN_PASSWORD_LENGTH} characters.\n` +
        style.dim(
          "  Length is the only requirement. A memorable passphrase of four\n" +
            "  or five words beats a short scrambled one.\n",
        ),
    );
    return null;
  }

  if ((await promptHidden("Confirm: ")) !== password) {
    console.error(`\n${style.red("The two entries did not match.")}\n`);
    return null;
  }

  return password;
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

async function create(email: string, admin: boolean): Promise<void> {
  const password = await promptNewPassword();
  if (!password) {
    process.exitCode = 1;
    return;
  }

  try {
    const user = await createUser(email, password, admin ? "admin" : "viewer");
    console.log(
      `\n${style.green("Created")} ${user.email} ${style.dim(`(${user.role})`)}\n`,
    );
  } catch (error) {
    if (error instanceof DuplicateUserError) {
      console.error(`\n${style.red("Already exists:")} ${error.message}\n`);
      process.exitCode = 1;
      return;
    }
    throw error;
  }
}

async function list(): Promise<void> {
  const users = await listUsers();

  if (users.length === 0) {
    console.log(
      `\n${style.yellow("No accounts yet.")}\n` +
        style.dim("  Create one with: npm run user:create -- you@example.com --admin\n"),
    );
    return;
  }

  console.log(`\n${style.bold(`Accounts (${users.length})`)}`);
  for (const user of users) {
    const lastLogin = user.lastLoginAt
      ? user.lastLoginAt.toISOString()
      : "never signed in";
    console.log(
      `  ${user.email.padEnd(32)} ${
        user.role === "admin" ? style.yellow("admin ") : "viewer"
      } ${style.dim(lastLogin)}`,
    );
  }
  console.log("");
}

async function passwd(email: string): Promise<void> {
  const user = await findUserByEmail(email);
  if (!user) {
    console.error(`\n${style.red("No such account:")} ${email}\n`);
    process.exitCode = 1;
    return;
  }

  const password = await promptNewPassword();
  if (!password) {
    process.exitCode = 1;
    return;
  }

  await setPassword(user.id, password);
  console.log(
    `\n${style.green("Password changed")} for ${user.email}\n` +
      style.dim("  All existing sessions for this account were invalidated.\n"),
  );
}

async function revoke(email: string): Promise<void> {
  const user = await findUserByEmail(email);
  if (!user) {
    console.error(`\n${style.red("No such account:")} ${email}\n`);
    process.exitCode = 1;
    return;
  }

  const version = await revokeSessions(user.id);
  console.log(
    `\n${style.green("Sessions revoked")} for ${user.email} ` +
      style.dim(`(token version now ${version})`) +
      "\n" +
      style.dim("  Every token issued to this account stops working immediately.\n"),
  );
}

async function remove(email: string): Promise<void> {
  const user = await findUserByEmail(email);
  if (!user) {
    console.error(`\n${style.red("No such account:")} ${email}\n`);
    process.exitCode = 1;
    return;
  }

  await deleteUser(user.id);
  console.log(
    `\n${style.green("Deleted")} ${user.email}\n` +
      style.dim(
        "  Their triage history is kept: triage_events records the actor's\n" +
          "  email as text so removing an account cannot erase the audit trail.\n",
      ),
  );
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/** Commands that operate on one named account. */
const EMAIL_COMMANDS = new Set(["create", "passwd", "revoke", "delete"]);

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);

  if (!command || command === "--help") {
    printUsage();
    if (!command) process.exitCode = 2;
    return;
  }

  const admin = rest.includes("--admin");
  const email = rest.find((argument) => !argument.startsWith("--"));

  if (EMAIL_COMMANDS.has(command) && !email) {
    console.error(`\n${style.red("An email address is required.")}`);
    printUsage();
    process.exitCode = 2;
    return;
  }

  const config = databaseConfig();
  console.log(
    `\nCloudSentinel accounts ${style.dim(describeConnection(config))}`,
  );

  // Fail fast with one clear sentence rather than a driver stack trace.
  await assertDatabaseReachable();

  switch (command) {
    case "create":
      await create(email!, admin);
      break;
    case "list":
      await list();
      break;
    case "passwd":
      await passwd(email!);
      break;
    case "revoke":
      await revoke(email!);
      break;
    case "delete":
      await remove(email!);
      break;
    default:
      console.error(`\n${style.red("Unknown command:")} ${command}`);
      printUsage();
      process.exitCode = 2;
  }
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
