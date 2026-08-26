/**
 * CloudSentinel — encoding finding ids for use in URLs.
 *
 * Where it sits in the architecture:
 *
 *   findings list --> encodeFindingId() --> /findings/<token>
 *                                              |
 *   route handler <-- decodeFindingId() <------+
 *
 * ## Why this is needed
 *
 * The rule engine builds a finding's id as `<ruleId>|<resourceId>|<key>`, and
 * both of the last two parts routinely contain forward slashes:
 *
 *   ec2-unrestricted-ingress|arn:aws:ec2:us-east-1:000000000000:security-group/sg-7262af|ipv4:tcp/22
 *
 * That id cannot be dropped into a URL path segment. Percent-encoding the
 * slashes does not reliably help either: `%2F` in a path is normalised or
 * rejected by a surprising number of servers, proxies, and frameworks, and code
 * that works locally and breaks behind a reverse proxy is the worst kind of
 * bug — it appears only in the environment where it is hardest to debug.
 *
 * The id shape itself is not up for negotiation. It is deterministic on
 * purpose, it is the primary key of the `findings` table, and it is what lets a
 * re-scan recognise a problem it has seen before rather than filing a fresh
 * one. Changing it to be URL-friendly would trade a real property for a
 * cosmetic one.
 *
 * So the id is base64url-encoded when it goes into a URL and decoded on the way
 * back. base64url is exactly the alphabet designed for this — `-` and `_`
 * instead of `+` and `/`, no padding — and it is the same encoding
 * lib/auth/jwt.ts uses, so there is one such scheme in the project rather than
 * two.
 *
 * The cost is that the URL is opaque: `/findings/ZWMyLXVucmVzdHJ...` says
 * nothing to a human reading it. That is an acceptable trade for an internal
 * dashboard, and the finding's real id is shown on the page itself.
 *
 * SECURITY: this is an *encoding*, not a signature or a secret. Anyone can
 * decode a token or craft one for an arbitrary id, which is fine — the id is
 * not a capability. Every route that accepts one still authenticates the
 * caller, and every lookup is a parameterised query that either matches a row
 * or returns 404.
 */

/** Longest encoded id accepted, so a decode cannot be handed unbounded input. */
const MAX_TOKEN_LENGTH = 2048;

/**
 * Encodes a finding id for use in a URL path segment.
 *
 * @param id - the finding's real id.
 * @returns a base64url token containing no character that needs escaping.
 */
export function encodeFindingId(id: string): string {
  return Buffer.from(id, "utf8").toString("base64url");
}

/**
 * Decodes a token from a URL back into a finding id.
 *
 * Node's base64 decoder silently ignores characters outside the alphabet rather
 * than reporting them, so the input is validated first. Without that check two
 * different tokens could decode to the same id, and a route would answer for a
 * URL it should have rejected.
 *
 * @param token - the path segment.
 * @returns the decoded id, or `null` if the token is empty, over-long, or not
 *   valid base64url. Callers turn `null` into a 404 — the same answer a
 *   well-formed token for a non-existent finding gets, so nothing about the
 *   response distinguishes "malformed" from "no such finding".
 */
export function decodeFindingId(token: string): string | null {
  if (token.length === 0 || token.length > MAX_TOKEN_LENGTH) return null;
  if (!/^[A-Za-z0-9_-]+$/.test(token)) return null;

  const decoded = Buffer.from(token, "base64url").toString("utf8");
  if (decoded.length === 0) return null;

  // A round-trip check. It rejects tokens whose bytes are not valid UTF-8 —
  // those decode to replacement characters, which would otherwise become a
  // lookup for an id nobody could ever have issued.
  if (encodeFindingId(decoded) !== token) return null;

  return decoded;
}
