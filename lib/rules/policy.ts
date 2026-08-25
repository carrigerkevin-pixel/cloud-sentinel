/**
 * CloudSentinel — IAM/S3 policy analysis helpers.
 *
 * Shared, side-effect-free functions for reasoning about AWS JSON policy
 * documents. The S3 and IAM rules in lib/rules/{s3,iam}.ts both need to answer
 * questions like "does this statement let anyone on the internet read the
 * bucket?" and "does this grant unrestricted administrative access?", and the
 * answers are fiddlier than they look. Putting that logic in one tested place
 * means a subtle policy-parsing bug gets fixed once instead of three times.
 *
 * Where it sits in the architecture: a leaf utility under the rule engine.
 * It imports only types, touches no network, and knows nothing about findings.
 *
 *   Resource.config.policy --> [ these helpers ] --> a rule's true/false answer
 *
 * Why AWS policy evaluation is hard to get right, and what this file does and
 * does not attempt:
 *
 *   - Every element accepts a string *or* an array of strings. `Action: "s3:*"`
 *     and `Action: ["s3:*"]` are the same policy. Code that only handles one
 *     shape silently misses half of all real policies.
 *   - Wildcards are glob-style, not regex: `*` matches any run of characters
 *     and `?` matches one. `s3:Get*` covers `s3:GetObject`, and action matching
 *     is case-insensitive in AWS.
 *   - `Principal: "*"`, `Principal: { "AWS": "*" }`, and
 *     `Principal: { "AWS": ["*"] }` all mean anonymous public access. A public
 *     bucket check that only looks for the first spelling is a false negative
 *     waiting to happen.
 *   - A `Condition` block can make an otherwise terrifying statement safe —
 *     `Action: "*"` restricted to one source IP and MFA-authenticated sessions
 *     is a legitimate break-glass policy. So the helpers here report whether a
 *     grant is *unconditional*, and the rules only flag unconditional ones.
 *
 * Deliberately NOT attempted: this is not a full IAM policy evaluator. It does
 * not resolve `Deny` precedence across multiple policies, expand
 * `NotAction`/`NotResource`, evaluate condition operators, or apply permission
 * boundaries or SCPs. Doing that properly is the job of AWS's own policy
 * simulator. What these helpers do is detect the specific, unambiguous
 * misconfigurations CloudSentinel reports on — and where a document uses a
 * construct they cannot reason about, the caller is expected to report the
 * check as *inconclusive* rather than guessing. Over-claiming here would be
 * worse than checking less: a scanner that quietly mis-evaluates a policy is
 * more dangerous than one that admits it does not know.
 */

import type {
  PolicyDocument,
  PolicyPrincipal,
  PolicyStatement,
} from "../types/resource.ts";

// ---------------------------------------------------------------------------
// Shape normalization
// ---------------------------------------------------------------------------

/**
 * Normalizes AWS's "string or array of strings" fields into a plain array.
 *
 * @param value - a single value, an array, `undefined`, or `null`.
 * @returns an array — empty when the field was absent. Never `undefined`, so
 *   callers can iterate without a null check.
 */
export function toArray<T>(value: T | T[] | undefined | null): T[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

/**
 * Flattens a `Principal` element into the list of principal identifiers it
 * names.
 *
 * Handles all three spellings AWS accepts: the bare string `"*"`, and the
 * object form mapping a category (`AWS`, `Service`, `Federated`,
 * `CanonicalUser`) to one or more identifiers.
 *
 * @param principal - the raw `Principal` value, or `undefined` on
 *   identity-based policies where the principal is implied.
 * @returns every identifier mentioned, in no particular order. Empty for
 *   `undefined`.
 */
export function principalIdentifiers(
  principal: PolicyPrincipal | undefined,
): string[] {
  if (principal === undefined) return [];
  if (typeof principal === "string") return [principal];
  return Object.values(principal).flatMap((value) => toArray(value));
}

// ---------------------------------------------------------------------------
// Wildcard matching
// ---------------------------------------------------------------------------

/** Characters that are special in a regular expression but literal in an ARN. */
const REGEX_SPECIALS = /[.+^${}()|[\]\\]/g;

/**
 * Tests an AWS wildcard pattern against a concrete value.
 *
 * AWS policy wildcards are glob-style, not regular expressions: `*` matches any
 * run of characters (including none) and `?` matches exactly one. Everything
 * else — including `.`, `+`, and `$`, all of which appear in real ARNs — is a
 * literal and must be escaped before the pattern is turned into a regex.
 *
 * Matching is case-insensitive because AWS treats action names that way:
 * `s3:getobject` and `s3:GetObject` are the same action, and a case-sensitive
 * comparison would miss a policy written in the wrong case.
 *
 * @param pattern - the pattern from the policy, e.g. `"s3:Get*"`.
 * @param value - the concrete string to test, e.g. `"s3:GetObject"`.
 * @returns true when the pattern covers the value.
 */
export function wildcardMatches(pattern: string, value: string): boolean {
  const source = pattern
    .replace(REGEX_SPECIALS, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${source}$`, "i").test(value);
}

/**
 * Whether a pattern is the unrestricted wildcard.
 *
 * Both `"*"` and `"*:*"` appear in the wild and mean the same thing: every
 * action in every service. They are checked together so no rule has to
 * remember the second spelling exists.
 */
export function isFullWildcard(pattern: string): boolean {
  const trimmed = pattern.trim();
  return trimmed === "*" || trimmed === "*:*";
}

// ---------------------------------------------------------------------------
// Statement predicates
// ---------------------------------------------------------------------------

/**
 * Whether a statement is guarded by any `Condition` block.
 *
 * Used as a safety valve throughout: a wildcard grant restricted to a corporate
 * IP range, an MFA-authenticated session, or a specific VPC endpoint is a
 * legitimate pattern, and flagging it as though it were unconditional would
 * train whoever reads the dashboard to ignore the tool. CloudSentinel does not
 * evaluate condition operators, so it treats "has a condition" as "cannot
 * confidently call this unrestricted" and stays quiet.
 *
 * The trade-off is explicit: this can hide a genuinely dangerous statement
 * whose condition is cosmetic (`StringLike` on a wildcard, say). That is
 * accepted because the alternative — a stream of false positives on every
 * correctly-written conditional policy — destroys the tool's credibility
 * faster.
 */
export function hasCondition(statement: PolicyStatement): boolean {
  return (
    statement.Condition !== undefined &&
    Object.keys(statement.Condition).length > 0
  );
}

/**
 * Whether a statement uses `NotAction`, `NotResource`, or `NotPrincipal`.
 *
 * These invert the meaning of the element they replace, and reasoning about
 * them correctly requires knowing the full universe of actions or principals —
 * which CloudSentinel does not have. A statement using one is therefore
 * something the helpers here cannot evaluate, and rules should surface that as
 * *inconclusive* rather than pass or fail. Guessing in either direction would
 * be dishonest: a `NotAction` statement is frequently *broader* than it looks.
 */
export function usesInvertedElement(statement: PolicyStatement): boolean {
  return (
    statement.NotAction !== undefined ||
    statement.NotResource !== undefined ||
    statement.NotPrincipal !== undefined
  );
}

/**
 * Whether a statement grants a specific action, allowing for wildcards.
 *
 * @param statement - the statement to inspect.
 * @param action - the concrete action to test for, e.g. `"iam:PassRole"`.
 * @param options.ignoreBareWildcard - when true, a bare `Action: "*"` does not
 *   count as granting the action. Set by rules that already have a dedicated
 *   check for full administrative access, so the same policy is not reported
 *   twice under two different headlines. A narrower wildcard such as `"iam:*"`
 *   still counts — that genuinely is a targeted grant of the action.
 * @returns true only for `Allow` statements. `Deny` statements are ignored
 *   here; see the file header on what this module does not attempt.
 */
export function statementGrantsAction(
  statement: PolicyStatement,
  action: string,
  options: { ignoreBareWildcard?: boolean } = {},
): boolean {
  if (statement.Effect !== "Allow") return false;
  return toArray(statement.Action).some((pattern) => {
    if (options.ignoreBareWildcard && isFullWildcard(pattern)) return false;
    return wildcardMatches(pattern, action);
  });
}

/**
 * Whether a statement applies to every resource (`Resource: "*"`).
 *
 * A statement with no `Resource` element at all is treated as unrestricted:
 * that shape appears on identity-based policies where the element was simply
 * omitted, and reading a missing restriction as "restricted" is the wrong
 * direction to err in for a security tool.
 */
export function statementCoversAllResources(
  statement: PolicyStatement,
): boolean {
  const resources = toArray(statement.Resource);
  if (resources.length === 0) return true;
  return resources.some((resource) => isFullWildcard(resource));
}

/**
 * Whether a statement grants unrestricted administrative access — the
 * `Action: "*"` on `Resource: "*"` pattern.
 *
 * Requires all four of: `Effect: "Allow"`, a full wildcard action, a full
 * wildcard resource, and no `Condition`. This is the single most dangerous
 * shape a policy can take, since it makes the holder equivalent to the account
 * root for everything except billing.
 */
export function isAdminStatement(statement: PolicyStatement): boolean {
  if (statement.Effect !== "Allow") return false;
  if (hasCondition(statement)) return false;
  if (!toArray(statement.Action).some(isFullWildcard)) return false;
  return statementCoversAllResources(statement);
}

/**
 * Whether a statement grants access to anonymous or arbitrary AWS principals.
 *
 * Two distinct dangers are folded together deliberately. `"*"` means literally
 * anyone on the internet, with no credentials. The `AuthenticatedUsers` idiom
 * — any principal with *some* AWS account — is barely better, since anyone can
 * create an AWS account in minutes. Both make the resource effectively public.
 *
 * Only meaningful on resource-based policies (bucket policies, trust
 * policies). Identity-based policies have no `Principal` element and this
 * returns false for them.
 */
export function statementHasPublicPrincipal(
  statement: PolicyStatement,
): boolean {
  return principalIdentifiers(statement.Principal).some((identifier) =>
    isFullWildcard(identifier),
  );
}

// ---------------------------------------------------------------------------
// Document-level queries
// ---------------------------------------------------------------------------

/**
 * Returns every statement in a document that grants unrestricted admin access.
 *
 * @param document - a parsed policy, or null when the collector could not read
 *   one.
 * @returns matching statements, or an empty array for a null document. Callers
 *   must not read "empty" as "safe" for a null document — check the resource's
 *   `unobserved` list first and report *inconclusive*, since a policy nobody
 *   managed to fetch could say anything at all.
 */
export function findAdminStatements(
  document: PolicyDocument | null,
): PolicyStatement[] {
  if (document === null) return [];
  return document.Statement.filter(isAdminStatement);
}

/**
 * Returns every statement that grants `action` against all resources with no
 * conditions attached.
 *
 * The combination is what makes a grant dangerous: `iam:PassRole` scoped to one
 * role ARN is ordinary and necessary, while `iam:PassRole` on `"*"` lets the
 * holder hand any role in the account — including an administrator role — to a
 * service they control. That is a textbook privilege-escalation path.
 *
 * @param document - a parsed policy, or null.
 * @param action - the concrete action to look for.
 * @param options.ignoreBareWildcard - see {@link statementGrantsAction}.
 */
export function findUnrestrictedActionStatements(
  document: PolicyDocument | null,
  action: string,
  options: { ignoreBareWildcard?: boolean } = {},
): PolicyStatement[] {
  if (document === null) return [];
  return document.Statement.filter(
    (statement) =>
      statementGrantsAction(statement, action, options) &&
      statementCoversAllResources(statement) &&
      !hasCondition(statement),
  );
}

/**
 * Returns every statement that grants `action` to a public principal without
 * conditions — the shape that makes an S3 bucket world-readable.
 *
 * @param document - a parsed bucket policy, or null.
 * @param action - the concrete action, e.g. `"s3:GetObject"`.
 */
export function findPublicStatements(
  document: PolicyDocument | null,
  action: string,
): PolicyStatement[] {
  if (document === null) return [];
  return document.Statement.filter(
    (statement) =>
      statementHasPublicPrincipal(statement) &&
      statementGrantsAction(statement, action) &&
      !hasCondition(statement),
  );
}

/**
 * Returns statements a rule cannot safely evaluate, so the caller can report
 * *inconclusive* instead of a false clean result.
 *
 * Currently that means statements using `NotAction`, `NotResource`, or
 * `NotPrincipal`. See {@link usesInvertedElement} for why those are out of
 * scope.
 */
export function findUnevaluatableStatements(
  document: PolicyDocument | null,
): PolicyStatement[] {
  if (document === null) return [];
  return document.Statement.filter(usesInvertedElement);
}

// ---------------------------------------------------------------------------
// Rendering evidence
// ---------------------------------------------------------------------------

/**
 * Renders a statement as a compact one-line summary for a finding's `detail`.
 *
 * Findings are read by someone deciding whether to act, so the evidence has to
 * quote the policy rather than describe it — `Allow "*" on "*"` is checkable at
 * a glance, "overly permissive policy" is not. The `Sid` is included when the
 * policy author supplied one, because that is the handle they will search for
 * when they go to fix it.
 *
 * Long lists are truncated to keep a single finding from filling the terminal;
 * the full document is always available in the resource's `policyRaw`.
 */
export function describeStatement(statement: PolicyStatement): string {
  const label = statement.Sid ? `Sid "${statement.Sid}": ` : "";
  const actions = renderList(toArray(statement.Action ?? statement.NotAction));
  const actionKey = statement.NotAction ? "NotAction" : "Action";
  const resources = renderList(
    toArray(statement.Resource ?? statement.NotResource),
  );
  const resourceKey = statement.NotResource ? "NotResource" : "Resource";

  const parts = [
    `${label}${statement.Effect} ${actionKey}=${actions}`,
    `${resourceKey}=${resources}`,
  ];

  const principals = principalIdentifiers(
    statement.Principal ?? statement.NotPrincipal,
  );
  if (principals.length > 0) {
    const principalKey = statement.NotPrincipal ? "NotPrincipal" : "Principal";
    parts.push(`${principalKey}=${renderList(principals)}`);
  }

  if (hasCondition(statement)) {
    parts.push(`Condition=${Object.keys(statement.Condition!).join(",")}`);
  }

  return parts.join(" ");
}

/**
 * Derives a short, stable key identifying one statement within a document.
 *
 * Findings need an id that survives re-scanning, and a statement's position in
 * the array is not it: adding a statement to the top of a policy would
 * renumber every finding below it and look to the dashboard like every old
 * problem was resolved and an identical set of new ones appeared. So the key is
 * the author-supplied `Sid` where there is one, and otherwise a hash of the
 * statement's own content — which changes only when the statement itself does,
 * which is exactly when it should be treated as a different finding.
 *
 * The hash is djb2, chosen because it is four lines of code with no
 * dependencies. It is *not* a cryptographic hash and must never be used where
 * collision resistance matters; here a collision would at worst merge two
 * findings on the same resource under the same rule.
 *
 * @param statement - the statement to key.
 * @returns the `Sid`, or an 8-character hex digest of the statement.
 */
export function statementKey(statement: PolicyStatement): string {
  if (statement.Sid) return statement.Sid;
  const json = JSON.stringify(statement);
  let hash = 5381;
  for (let index = 0; index < json.length; index += 1) {
    // `| 0` keeps the running value a 32-bit int; without it the number drifts
    // into float territory and the digest stops being reproducible.
    hash = ((hash << 5) + hash + json.charCodeAt(index)) | 0;
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}

/**
 * Renders a list of policy values, showing at most three and counting the rest.
 *
 * Three is enough to recognise the statement without a wide policy pushing the
 * genuinely important part of the message off the edge of a terminal.
 */
function renderList(values: string[]): string {
  if (values.length === 0) return "(none)";
  const shown = values.slice(0, 3).map((value) => `"${value}"`);
  const extra = values.length - shown.length;
  return extra > 0 ? `${shown.join(",")} +${extra} more` : shown.join(",");
}
