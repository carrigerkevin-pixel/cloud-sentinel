/**
 * CloudSentinel — the triage vocabulary.
 *
 * The states a finding can be triaged into, and the small pure helpers that go
 * with them. Types and constants only — **no imports that reach the database**.
 *
 * Where it sits in the architecture:
 *
 *   [ this file ]
 *     +--> lib/db/triage.ts               reads and writes (server only)
 *     +--> lib/ui/format.ts               labels and badge styling
 *     +--> app/components/TriageControl   the browser
 *     +--> app/api/... routes             request validation
 *
 * ## Why this is a separate file
 *
 * This is the same split as lib/rules/types.ts and lib/types/resource.ts, and
 * here it is load-bearing rather than tidy.
 *
 * The triage control is a client component: its code is bundled and sent to the
 * browser. It needs the list of valid states and the note length limit. If it
 * imported those from lib/db/triage.ts, the bundler would follow that module's
 * own imports — `./client.ts`, and from there `pg` — and try to include the
 * PostgreSQL driver in a browser bundle. That fails to build, and it fails for
 * a good reason: database connection code has no business being shipped to a
 * client, where at best it is dead weight and at worst it discloses how the
 * server talks to its database.
 *
 * A `import type` would be erased and cause no such problem, but
 * {@link MAX_NOTE_LENGTH} is a real value the form needs at runtime. So the
 * vocabulary lives here, where both sides can import it safely, and
 * lib/db/triage.ts re-exports it so server-side callers still have one obvious
 * place to import from.
 */

// ---------------------------------------------------------------------------
// States
// ---------------------------------------------------------------------------

/**
 * What a person has decided about a finding.
 *
 * `suppressed` and `false_positive` both hide a finding from the default view,
 * and are deliberately kept apart. One is a statement about the business — the
 * risk is real and has been accepted. The other is a bug report about the rule
 * set. Collapsing them into a single "ignore" would throw away the only signal
 * that says which rules are miscalibrated and need retuning.
 */
export type TriageState =
  | "untriaged"
  | "acknowledged"
  | "suppressed"
  | "false_positive";

/** Every valid state, for validating values arriving from the network. */
export const TRIAGE_STATES: readonly TriageState[] = [
  "untriaged",
  "acknowledged",
  "suppressed",
  "false_positive",
];

/**
 * States that hide a finding from the default dashboard view.
 *
 * `acknowledged` is deliberately not one of them: acknowledging a finding means
 * "yes, this is real, it is on the list", which is a reason to keep looking at
 * it rather than to stop.
 */
export const HIDDEN_STATES: readonly TriageState[] = [
  "suppressed",
  "false_positive",
];

/**
 * Type guard for a value arriving in a request body or query string.
 *
 * @returns `true` only for one of the four known states.
 */
export function isTriageState(value: unknown): value is TriageState {
  return (
    typeof value === "string" &&
    (TRIAGE_STATES as readonly string[]).includes(value)
  );
}

// ---------------------------------------------------------------------------
// Constraints
// ---------------------------------------------------------------------------

/**
 * Longest justification accepted.
 *
 * Generous for prose and bounded against abuse. Enforced in three places, on
 * purpose: the form uses it as a `maxLength` so the limit is visible while
 * typing, the API route rejects an over-long note before it reaches the
 * database, and lib/db/triage.ts checks it again because the route is not the
 * only possible caller.
 */
export const MAX_NOTE_LENGTH = 2000;

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/** The current triage decision on a finding. */
export interface Triage {
  findingId: string;
  state: TriageState;
  note: string | null;
  updatedBy: number | null;
  updatedAt: Date;
}

/** One entry in a finding's triage history. */
export interface TriageEvent {
  id: number;
  findingId: string;
  previousState: TriageState | null;
  newState: TriageState;
  note: string | null;
  /**
   * The actor's email, stored as plain text rather than joined from `users`.
   *
   * This is what makes the trail survive the account being deleted. An audit
   * log that can be erased by removing a user is not an audit log.
   */
  actorEmail: string;
  createdAt: Date;
}
