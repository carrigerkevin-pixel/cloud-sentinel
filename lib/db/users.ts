/**
 * CloudSentinel — dashboard user accounts.
 *
 * Every read and write against the `users` table lives here: creating an
 * account, checking a login, revoking sessions, and re-checking a token holder
 * against the current database state.
 *
 * Where it sits in the architecture:
 *
 *   scripts/user.ts  ------------+
 *                                |
 *   POST /api/auth/login --------+--> [ this file ] --> users (Postgres)
 *                                |          |
 *   every authenticated request -+          +--> lib/auth/password.ts
 *                                           +--> lib/auth/jwt.ts (claims only)
 *
 * Entry point: `npm run user:create`.
 *
 * ## Why authentication lives in the database layer
 *
 * {@link authenticate} could have been assembled in the login route out of a
 * lookup plus a `verifyPassword` call. It is here instead because the safe
 * version of that sequence has three easy-to-omit steps — the decoy hash, the
 * `last_login_at` write, and the opportunistic rehash — and a second caller
 * that reimplements the sequence will omit at least one of them. One function
 * that is correct once is worth more than a convention.
 */

import {
  DECOY_PASSWORD_HASH,
  hashPassword,
  needsRehash,
  verifyPassword,
} from "../auth/password.ts";
import { query } from "./client.ts";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** The two roles the dashboard understands. */
export type UserRole = "admin" | "viewer";

/**
 * A user account as the application sees it.
 *
 * Note what is absent: `password_hash` never leaves this file. Returning it
 * would put a hash into route handlers, log lines, and JSON responses, and the
 * only code that has any business reading it is {@link authenticate} a few
 * lines below.
 */
export interface User {
  id: number;
  email: string;
  role: UserRole;
  /** Current token version. A JWT whose `tv` claim differs is no longer valid. */
  tokenVersion: number;
  createdAt: Date;
  lastLoginAt: Date | null;
}

/** Raw row shape, including the hash the public {@link User} deliberately omits. */
interface UserRow {
  id: string;
  email: string;
  role: UserRole;
  token_version: number;
  created_at: Date;
  last_login_at: Date | null;
  password_hash: string;
}

/**
 * Maps a row to the public shape.
 *
 * `id` is read as a string and converted here. Postgres `BIGINT` exceeds
 * JavaScript's safe integer range, so the `pg` driver returns it as a string
 * rather than silently losing precision. Converting in one place keeps that
 * detail from leaking into every caller.
 */
function toUser(row: UserRow): User {
  return {
    id: Number(row.id),
    email: row.email,
    role: row.role,
    tokenVersion: row.token_version,
    createdAt: row.created_at,
    lastLoginAt: row.last_login_at,
  };
}

/**
 * Normalises an email to its canonical stored form.
 *
 * The database enforces `email = lower(email)`, so this is not merely a
 * convenience: skipping it turns a mixed-case address into a constraint
 * violation on insert, and into a silent no-match on lookup. Doing it in one
 * exported helper means the login route and the account-creation CLI cannot
 * disagree about what counts as the same address.
 */
export function normaliseEmail(email: string): string {
  return email.trim().toLowerCase();
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

const SELECT_COLUMNS = `id, email, role, token_version, created_at, last_login_at, password_hash`;

/**
 * Looks up a user by id.
 *
 * @returns the user, or `null` if no such account exists — which includes the
 *   case of an account deleted while its token was still valid.
 */
export async function findUserById(id: number): Promise<User | null> {
  const rows = await query<UserRow>(
    `SELECT ${SELECT_COLUMNS} FROM users WHERE id = $1`,
    [id],
  );
  return rows[0] ? toUser(rows[0]) : null;
}

/** Looks up a user by email. The address is normalised before the lookup. */
export async function findUserByEmail(email: string): Promise<User | null> {
  const rows = await query<UserRow>(
    `SELECT ${SELECT_COLUMNS} FROM users WHERE email = $1`,
    [normaliseEmail(email)],
  );
  return rows[0] ? toUser(rows[0]) : null;
}

/** Lists all accounts, oldest first. Backs `npm run user:list`. */
export async function listUsers(): Promise<User[]> {
  const rows = await query<UserRow>(
    `SELECT ${SELECT_COLUMNS} FROM users ORDER BY created_at`,
  );
  return rows.map(toUser);
}

/** Counts accounts. Used to detect a fresh install with no way to log in. */
export async function countUsers(): Promise<number> {
  const rows = await query<{ count: string }>(
    `SELECT COUNT(*)::text AS count FROM users`,
  );
  return Number(rows[0]?.count ?? 0);
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/** Raised when an account already exists for an email address. */
export class DuplicateUserError extends Error {
  constructor(email: string) {
    super(`An account already exists for ${email}.`);
    this.name = "DuplicateUserError";
  }
}

/**
 * Shortest password accepted when creating an account.
 *
 * Length is the only rule. Composition requirements — a digit, a symbol, a
 * capital — are deliberately absent: they measurably push people toward
 * `Password1!` and its variants, which is why NIST SP 800-63B dropped them.
 * A long passphrase beats a short scrambled word, and the scrypt cost in
 * lib/auth/password.ts is what defends the short end of the range.
 */
export const MIN_PASSWORD_LENGTH = 12;

/**
 * Creates an account.
 *
 * @param email - the address, normalised before storage.
 * @param password - plaintext, hashed here and never stored or logged.
 * @param role - defaults to `viewer`, the least-privileged option. Making the
 *   safe value the default means forgetting the argument cannot accidentally
 *   mint an administrator.
 * @returns the created user.
 * @throws {DuplicateUserError} if the email is taken.
 * @throws if the email is empty or the password is shorter than
 *   {@link MIN_PASSWORD_LENGTH}.
 */
export async function createUser(
  email: string,
  password: string,
  role: UserRole = "viewer",
): Promise<User> {
  const normalised = normaliseEmail(email);

  if (normalised.length === 0) {
    throw new Error("An email address is required.");
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new Error(
      `Password must be at least ${MIN_PASSWORD_LENGTH} characters. ` +
        "A long passphrase is stronger than a short scrambled word.",
    );
  }

  const passwordHash = await hashPassword(password);

  try {
    const rows = await query<UserRow>(
      `INSERT INTO users (email, password_hash, role)
            VALUES ($1, $2, $3)
         RETURNING ${SELECT_COLUMNS}`,
      [normalised, passwordHash, role],
    );
    return toUser(rows[0]!);
  } catch (error) {
    // 23505 is Postgres's unique_violation. Translated into a named error so
    // callers can report "that email is taken" without matching on driver
    // internals or, worse, on the text of an error message.
    if ((error as { code?: string }).code === "23505") {
      throw new DuplicateUserError(normalised);
    }
    throw error;
  }
}

/**
 * Replaces a user's password and invalidates all their existing sessions.
 *
 * SECURITY: the `token_version` bump is not optional housekeeping. A password
 * is most often changed precisely because it may have been exposed, and a JWT
 * already in an attacker's hands keeps working until it expires no matter what
 * the password becomes. Bumping the version in the same statement means the
 * change of password and the eviction of every existing session cannot come
 * apart.
 *
 * @returns `true` if a user was updated, `false` if the id does not exist.
 */
export async function setPassword(
  id: number,
  password: string,
): Promise<boolean> {
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new Error(
      `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`,
    );
  }

  const rows = await query<{ id: string }>(
    `UPDATE users
        SET password_hash = $2,
            token_version = token_version + 1
      WHERE id = $1
      RETURNING id`,
    [id, await hashPassword(password)],
  );
  return rows.length > 0;
}

/**
 * Invalidates every token currently held by a user, without changing anything
 * else.
 *
 * This is "log out everywhere", and the response to a suspected compromise.
 * It takes effect on the very next request, because verification compares the
 * token's `tv` claim against this column every time.
 *
 * @returns the new token version, or `null` if the user does not exist.
 */
export async function revokeSessions(id: number): Promise<number | null> {
  const rows = await query<{ token_version: number }>(
    `UPDATE users
        SET token_version = token_version + 1
      WHERE id = $1
      RETURNING token_version`,
    [id],
  );
  return rows[0]?.token_version ?? null;
}

/** Changes a user's role, and revokes their sessions so it takes effect at once. */
export async function setRole(id: number, role: UserRole): Promise<boolean> {
  // Sessions are revoked along with the change because the role is embedded in
  // every issued token. Without this, demoting an admin would leave them with
  // admin privileges until their current token happened to expire — which is
  // the wrong behaviour for the one operation whose entire purpose is taking a
  // privilege away.
  const rows = await query<{ id: string }>(
    `UPDATE users
        SET role = $2,
            token_version = token_version + 1
      WHERE id = $1
      RETURNING id`,
    [id, role],
  );
  return rows.length > 0;
}

/** Deletes an account. Triage history survives — see `triage_events.actor_email`. */
export async function deleteUser(id: number): Promise<boolean> {
  const rows = await query<{ id: string }>(
    `DELETE FROM users WHERE id = $1 RETURNING id`,
    [id],
  );
  return rows.length > 0;
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/**
 * Checks an email and password against the database.
 *
 * Three things happen here that are easy to leave out, and each is a real
 * defect if omitted.
 *
 * **The decoy hash.** When no account matches, the password is still verified —
 * against {@link DECOY_PASSWORD_HASH}, which nothing can match. Without it, an
 * unknown email would be answered in microseconds while a known one took the
 * ~100 ms scrypt costs, and that difference is easily measurable over a
 * network. It turns the login form into an oracle that confirms which addresses
 * hold accounts, which is the reconnaissance step before credential stuffing or
 * targeted phishing.
 *
 * **`last_login_at`.** Written only on success, so the column means what it
 * says and can be used later to spot dormant accounts.
 *
 * **Opportunistic rehashing.** A successful login is the only moment the
 * plaintext is legitimately available, so it is the only moment a hash stored
 * under weaker parameters can be upgraded. Skipping it would mean the oldest
 * passwords — the ones most likely to be reused on other sites — keep the
 * weakest protection forever.
 *
 * @returns the authenticated user, or `null`. The `null` deliberately does not
 *   distinguish "no such account" from "wrong password": the caller must not be
 *   able to tell them apart, because it must not tell the client either.
 */
export async function authenticate(
  email: string,
  password: string,
): Promise<User | null> {
  const rows = await query<UserRow>(
    `SELECT ${SELECT_COLUMNS} FROM users WHERE email = $1`,
    [normaliseEmail(email)],
  );
  const row = rows[0];

  const matched = await verifyPassword(
    password,
    row?.password_hash ?? DECOY_PASSWORD_HASH,
  );

  if (!row || !matched) return null;

  // Both writes are folded into a single statement so a successful login costs
  // one round trip rather than three.
  const upgraded = needsRehash(row.password_hash)
    ? await hashPassword(password)
    : null;

  const updated = await query<UserRow>(
    `UPDATE users
        SET last_login_at = now(),
            password_hash = COALESCE($2, password_hash)
      WHERE id = $1
      RETURNING ${SELECT_COLUMNS}`,
    [row.id, upgraded],
  );

  return toUser(updated[0] ?? row);
}

/**
 * Re-checks a token's claims against the live database.
 *
 * SECURITY: this is the step that makes a stateless token safe to use for
 * authorization. A verified JWT proves only that *we* issued it and that it has
 * not been altered — it says nothing about what has happened since. In eight
 * hours an account can be deleted, demoted from admin to viewer, or have its
 * sessions revoked, and the token in the user's cookie reflects none of that.
 *
 * So every authenticated request pays for one indexed primary-key lookup and
 * compares:
 *
 *   - the account still exists;
 *   - `token_version` still matches, so the session was not revoked;
 *   - the role in the token still matches the role in the database.
 *
 * The role comparison is what closes the privilege-escalation window. Without
 * it, a demoted administrator keeps administrative access until their token
 * expires, which makes the demotion advisory rather than effective.
 *
 * @param claims - the already-signature-verified claims from lib/auth/jwt.ts.
 *   Passing unverified claims here would defeat the entire scheme.
 * @returns the current user record, or `null` if the token should no longer be
 *   honoured.
 */
export async function userForClaims(claims: {
  sub: string;
  role: UserRole;
  tv: number;
}): Promise<User | null> {
  const id = Number(claims.sub);
  if (!Number.isInteger(id)) return null;

  const user = await findUserById(id);
  if (!user) return null;
  if (user.tokenVersion !== claims.tv) return null;
  if (user.role !== claims.role) return null;

  return user;
}
