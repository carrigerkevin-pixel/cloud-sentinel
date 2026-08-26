/**
 * CloudSentinel — password hashing and verification.
 *
 * Turns a password into something safe to store, and checks a login attempt
 * against it. Used by the dashboard's authentication layer.
 *
 * Where it sits in the architecture:
 *
 *   login request --> [ this file ] --> users.password_hash (Postgres)
 *                          |
 *                          +--> lib/auth/jwt.ts issues a token on success
 *
 * This file has no dependencies beyond `node:crypto`. That is a deliberate
 * choice and not just minimalism: password hashing is a place where an
 * unmaintained transitive dependency is a genuine liability, and scrypt is
 * already built into Node with the same construction bcrypt-style libraries
 * wrap.
 *
 * ## Why scrypt
 *
 * A password must never be stored in a form that can be reversed, so what gets
 * stored is a one-way hash. But a plain hash (SHA-256, say) is the wrong tool:
 * it is designed to be *fast*, and fast is exactly what an attacker holding a
 * stolen `users` table wants. Modern hardware computes billions of SHA-256
 * hashes per second, so every password in a common-passwords list gets tried
 * against every row in minutes.
 *
 * scrypt is deliberately slow, and — the part that matters — deliberately
 * *memory-hard*. Computing it requires holding a large working set in RAM,
 * which is the one resource a GPU or ASIC cannot cheaply multiply. That turns
 * an offline cracking run from "minutes" into "economically pointless" for
 * anything but the weakest passwords.
 *
 * ## Why a salt
 *
 * Each password gets its own random salt, mixed in before hashing. Without one,
 * identical passwords produce identical hashes: an attacker learns which users
 * share a password, and can precompute one rainbow table that attacks every
 * account in every breached database at once. With a per-user salt, that
 * precomputation is worthless and each account must be attacked individually.
 *
 * The salt is not a secret and is stored in plain sight alongside the hash.
 * Its job is uniqueness, not concealment.
 *
 * ## Storage format
 *
 *   scrypt$<N>$<r>$<p>$<salt-base64>$<hash-base64>
 *
 * The cost parameters travel with the hash rather than living only in this
 * file's constants. That is what allows {@link SCRYPT_N} to be raised in a year
 * without invalidating every existing password: an old hash still declares the
 * parameters it was created under, so it can still be verified, and
 * {@link needsRehash} then flags it to be upgraded at the next successful
 * login — the one moment the plaintext is legitimately available.
 */

import {
  randomBytes,
  scrypt,
  timingSafeEqual,
  type ScryptOptions,
} from "node:crypto";

/**
 * Promise wrapper around Node's callback-based `scrypt`.
 *
 * Written out rather than using `util.promisify`, because promisify resolves to
 * scrypt's three-argument overload and so loses the options parameter — which
 * is where every cost setting in this file lives. Wrapping it by hand keeps the
 * options fully type-checked instead of requiring a cast that would silence a
 * genuine mistake.
 */
function scryptAsync(
  password: string,
  salt: Buffer,
  keyLength: number,
  options: ScryptOptions,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keyLength, options, (error, derivedKey) => {
      if (error) reject(error);
      else resolve(derivedKey);
    });
  });
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/**
 * scrypt CPU/memory cost. Must be a power of two.
 *
 * 2^14 = 16384 is the value Node's own documentation uses as its example and a
 * common baseline for interactive logins. Memory use is roughly
 * `128 * N * r` bytes — about 16 MB here — and time is roughly 100 ms on this
 * machine. The trade-off is a real one in both directions: raising it hardens
 * every stored password, and also makes a login request slower and a flood of
 * login attempts more expensive to serve. 16384 sits where a person does not
 * notice the delay and an attacker does.
 */
const SCRYPT_N = 16384;

/** Block size. 8 is the standard value; it tunes memory use alongside N. */
const SCRYPT_R = 8;

/**
 * Parallelisation factor. 1 is standard for password storage.
 *
 * Raising it increases work for the defender and the attacker equally, so it
 * buys nothing here — N is the parameter that actually costs an attacker more
 * than it costs us.
 */
const SCRYPT_P = 1;

/** Derived key length in bytes. 32 matches SHA-256's output width. */
const KEY_LENGTH = 32;

/** Salt length in bytes. 16 bytes of CSPRNG output will never collide in practice. */
const SALT_LENGTH = 16;

/**
 * Upper bound on memory scrypt may allocate, in bytes.
 *
 * Node defaults this to 32 MB and throws if the parameters would exceed it.
 * `128 * N * r` is ~16 MB at the settings above, so the default would just
 * barely do — but it would start throwing the moment {@link SCRYPT_N} is
 * doubled, which is a confusing failure to hit while trying to *strengthen* the
 * hashing. Deriving the limit from the parameters removes that trap.
 */
const MAX_MEMORY = 128 * SCRYPT_N * SCRYPT_R * 2;

/** Prefix identifying the algorithm in the stored string. */
const ALGORITHM = "scrypt";

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/**
 * Hashes a password for storage.
 *
 * @param password - the plaintext password. Never logged, never stored, and not
 *   retained after this call returns.
 * @returns the encoded hash string, safe to write to `users.password_hash`.
 * @throws if the password is empty, or if scrypt itself fails (which in
 *   practice means the parameters exceed {@link MAX_MEMORY}).
 */
export async function hashPassword(password: string): Promise<string> {
  if (password.length === 0) {
    throw new Error("Cannot hash an empty password.");
  }

  const salt = randomBytes(SALT_LENGTH);
  const derived = await scryptAsync(password, salt, KEY_LENGTH, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: MAX_MEMORY,
  });

  return [
    ALGORITHM,
    SCRYPT_N,
    SCRYPT_R,
    SCRYPT_P,
    salt.toString("base64"),
    derived.toString("base64"),
  ].join("$");
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/** The parsed pieces of a stored hash string. */
interface ParsedHash {
  n: number;
  r: number;
  p: number;
  salt: Buffer;
  hash: Buffer;
}

/**
 * Parses a stored hash string back into its components.
 *
 * @returns the parsed parts, or `null` if the string is not a well-formed
 *   scrypt record. Returning `null` rather than throwing is deliberate: a
 *   corrupt row in the database must fail the login attempt, not crash the
 *   login endpoint for everybody.
 */
function parseHash(stored: string): ParsedHash | null {
  const parts = stored.split("$");
  if (parts.length !== 6) return null;

  const [algorithm, rawN, rawR, rawP, rawSalt, rawHash] = parts as [
    string,
    string,
    string,
    string,
    string,
    string,
  ];

  if (algorithm !== ALGORITHM) return null;

  const n = Number(rawN);
  const r = Number(rawR);
  const p = Number(rawP);
  if (!Number.isInteger(n) || !Number.isInteger(r) || !Number.isInteger(p)) {
    return null;
  }

  // SECURITY: the parameters come out of the database, and the database is what
  // an attacker with a SQL-injection foothold would control. Unbounded values
  // here would let a poisoned row demand terabytes of memory — a denial of
  // service triggered by an ordinary login attempt. The ceilings are far above
  // any parameters this project would legitimately choose and far below
  // anything that hurts.
  if (n < 2 || n > 1 << 20) return null;
  if (r < 1 || r > 64) return null;
  if (p < 1 || p > 16) return null;

  const salt = Buffer.from(rawSalt, "base64");
  const hash = Buffer.from(rawHash, "base64");
  if (salt.length === 0 || hash.length === 0) return null;

  return { n, r, p, salt, hash };
}

/**
 * Checks a password against a stored hash.
 *
 * The comparison is constant-time. A naive `===` on the two hashes leaks how
 * many leading bytes matched through how long the comparison took, which is
 * enough — over many attempts — to reconstruct the correct value one byte at a
 * time. `timingSafeEqual` always inspects every byte.
 *
 * @param password - the plaintext attempt.
 * @param stored - the encoded hash from `users.password_hash`.
 * @returns `true` only on a genuine match. A malformed stored hash, a length
 *   mismatch, or a scrypt failure all return `false` — never `true`, and never
 *   a thrown error that a caller might mistake for a different outcome.
 */
export async function verifyPassword(
  password: string,
  stored: string,
): Promise<boolean> {
  const parsed = parseHash(stored);
  if (!parsed) return false;

  let derived: Buffer;
  try {
    derived = await scryptAsync(password, parsed.salt, parsed.hash.length, {
      N: parsed.n,
      r: parsed.r,
      p: parsed.p,
      maxmem: 128 * parsed.n * parsed.r * 2,
    });
  } catch {
    return false;
  }

  // timingSafeEqual throws rather than returning false when the lengths differ,
  // so the lengths are checked first. This is not a timing leak: the length of
  // a hash is a property of the algorithm, not of the password.
  if (derived.length !== parsed.hash.length) return false;

  return timingSafeEqual(derived, parsed.hash);
}

/**
 * A syntactically valid hash that no password can ever match.
 *
 * SECURITY: this exists to close a user-enumeration side channel.
 *
 * If the login route skipped hashing whenever the email did not exist, it would
 * answer for unknown accounts in about a microsecond and for known ones in
 * about 100 ms. That difference is trivially measurable over the network, and
 * it turns the login form into an oracle that confirms which email addresses
 * hold accounts — the first step of a targeted credential-stuffing or phishing
 * campaign.
 *
 * So the login route verifies against this constant when it finds no user, and
 * the failing request costs the same as a genuine one. The salt and hash below
 * are just random bytes: they correspond to no password, so the comparison is
 * guaranteed to fail after doing the full amount of work.
 */
export const DECOY_PASSWORD_HASH =
  "scrypt$16384$8$1$FLXg4ZjdXj92rF+NNzfTow==$QG5R529JnjZnt3JP5fulNI/s2fVXQJ+wjA7mX3RjIw4=";

// ---------------------------------------------------------------------------
// Upgrading
// ---------------------------------------------------------------------------

/**
 * Reports whether a stored hash was created with weaker parameters than the
 * current ones.
 *
 * Called after a successful login — the only moment the plaintext password is
 * legitimately in memory and can be re-hashed. Without this, raising
 * {@link SCRYPT_N} would only ever protect accounts created afterwards, and the
 * oldest passwords (the ones most likely to be reused elsewhere) would stay at
 * the weakest setting forever.
 *
 * @param stored - the encoded hash from the database.
 * @returns `true` if the hash should be replaced. An unparseable hash returns
 *   `true` as well: something is wrong with it, and rewriting it at the current
 *   parameters is the correct repair.
 */
export function needsRehash(stored: string): boolean {
  const parsed = parseHash(stored);
  if (!parsed) return true;
  return parsed.n < SCRYPT_N || parsed.r < SCRYPT_R || parsed.p < SCRYPT_P;
}
