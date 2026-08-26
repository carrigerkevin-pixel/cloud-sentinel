/**
 * CloudSentinel — finding triage.
 *
 * Reads and writes the human decision about a finding: acknowledged, suppressed,
 * a false positive, or not yet looked at.
 *
 * Where it sits in the architecture:
 *
 *   PATCH /api/findings/<id>/triage --> [ this file ] --> finding_triage
 *                                                     --> triage_events
 *
 * ## The rule this file exists to enforce
 *
 * **Triage never changes `findings.status`.**
 *
 * `findings.status` is `open` or `resolved`, and only lib/db/lifecycle.ts sets
 * it, from what a scan actually observed. It is the scanner's claim about
 * reality. Triage is a person's claim about what should be *done*, and the two
 * are kept in different tables so that neither can quietly overwrite the other.
 *
 * If suppressing a finding also marked it resolved, CloudSentinel would report
 * a bucket as fixed because somebody clicked a button, and every compliance
 * report it produced would be worthless. So a finding can be suppressed and
 * still open at the same time: the bucket is still public, the tool still says
 * so, and suppression only moves it out of the default view.
 *
 * ## Why every change is also appended to a log
 *
 * `finding_triage` holds one row per finding — the current state, and nothing
 * else. On its own it cannot answer "who suppressed this, and when", because
 * the next change overwrites the last. `triage_events` is append-only and keeps
 * every transition with its actor, which is the difference between a status
 * field and an audit trail. The two writes happen in one transaction, so the
 * state and its history can never disagree.
 */

import { query, withTransaction } from "./client.ts";
import type { User } from "./users.ts";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * What a person has decided about a finding.
 *
 * `suppressed` and `false_positive` both hide a finding from the default view,
 * and are deliberately kept apart. One is a statement about the business — the
 * risk is real and accepted. The other is a bug report about the rule set.
 * Collapsing them into a single "ignore" would throw away the only signal that
 * says which rules are miscalibrated and need retuning.
 */
export type TriageState =
  | "untriaged"
  | "acknowledged"
  | "suppressed"
  | "false_positive";

/** Every valid state, for validating input from the network. */
export const TRIAGE_STATES: readonly TriageState[] = [
  "untriaged",
  "acknowledged",
  "suppressed",
  "false_positive",
];

/**
 * States that hide a finding from the default dashboard view.
 *
 * `acknowledged` is deliberately *not* one of them: acknowledging a finding
 * means "yes, this is real, it is on the list", which is a reason to keep
 * looking at it, not to stop.
 */
export const HIDDEN_STATES: readonly TriageState[] = [
  "suppressed",
  "false_positive",
];

/** Type guard for a value arriving from a request body. */
export function isTriageState(value: unknown): value is TriageState {
  return (
    typeof value === "string" &&
    (TRIAGE_STATES as readonly string[]).includes(value)
  );
}

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

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/** Longest justification accepted. Generous for prose, bounded against abuse. */
export const MAX_NOTE_LENGTH = 2000;

/**
 * Raised when a triage change is not allowed. Carries a message safe to show a
 * user, since every case is something they can correct.
 */
export class TriageValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TriageValidationError";
  }
}

/**
 * Checks a proposed change and returns the note to store.
 *
 * SECURITY: the note requirement is the point. Making an inconvenient critical
 * finding disappear is the easiest way to defeat a posture-management tool, and
 * requiring a written justification does not prevent it — it makes it
 * attributable. A suppression someone has to explain, under their own name, in
 * a log nobody can edit, is a very different act from one that takes a click.
 *
 * The same constraint exists in the database (`finding_triage_note_required` in
 * 0002_dashboard.sql). Checking here as well is not redundant: this produces a
 * sentence the user can act on, where the constraint produces a violation that
 * only proves the application let something through it should not have.
 *
 * @throws {TriageValidationError} if a hiding state has no justification, or
 *   the note is too long.
 */
function validate(state: TriageState, note: string | null): string | null {
  const trimmed = note?.trim() ?? "";

  if (trimmed.length > MAX_NOTE_LENGTH) {
    throw new TriageValidationError(
      `The note must be ${MAX_NOTE_LENGTH} characters or fewer.`,
    );
  }

  if (state === "untriaged") {
    // Returning to untriaged is "never mind" — there is nothing to justify, and
    // the database CHECK forbids a note here anyway.
    return null;
  }

  if (trimmed.length === 0) {
    throw new TriageValidationError(
      state === "acknowledged"
        ? "Say why this finding is being acknowledged."
        : "Hiding a finding requires a written justification.",
    );
  }

  return trimmed;
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

interface TriageRow {
  finding_id: string;
  state: TriageState;
  note: string | null;
  updated_by: string | null;
  updated_at: Date;
}

function toTriage(row: TriageRow): Triage {
  return {
    findingId: row.finding_id,
    state: row.state,
    note: row.note,
    updatedBy: row.updated_by === null ? null : Number(row.updated_by),
    updatedAt: row.updated_at,
  };
}

/**
 * Returns the triage record for a finding.
 *
 * @returns the record, or `null` when the finding has never been triaged. The
 *   absence of a row and the state `untriaged` mean the same thing to a reader;
 *   callers that need a value should treat `null` as `untriaged`. No row is
 *   written until someone actually makes a decision, so the table stays a
 *   record of decisions rather than a row per finding that has ever existed.
 */
export async function getTriage(findingId: string): Promise<Triage | null> {
  const rows = await query<TriageRow>(
    `SELECT finding_id, state, note, updated_by, updated_at
       FROM finding_triage
      WHERE finding_id = $1`,
    [findingId],
  );
  return rows[0] ? toTriage(rows[0]) : null;
}

interface TriageEventRow {
  id: string;
  finding_id: string;
  previous_state: TriageState | null;
  new_state: TriageState;
  note: string | null;
  actor_email: string;
  created_at: Date;
}

/**
 * Returns a finding's triage history, newest first.
 *
 * @param findingId - the finding to read.
 * @param limit - how many entries to return.
 */
export async function triageHistory(
  findingId: string,
  limit = 50,
): Promise<TriageEvent[]> {
  const rows = await query<TriageEventRow>(
    `SELECT id, finding_id, previous_state, new_state, note, actor_email, created_at
       FROM triage_events
      WHERE finding_id = $1
      ORDER BY created_at DESC, id DESC
      LIMIT $2`,
    [findingId, limit],
  );

  return rows.map((row) => ({
    id: Number(row.id),
    findingId: row.finding_id,
    previousState: row.previous_state,
    newState: row.new_state,
    note: row.note,
    actorEmail: row.actor_email,
    createdAt: row.created_at,
  }));
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/** Raised when the finding being triaged does not exist. */
export class UnknownFindingError extends Error {
  constructor(findingId: string) {
    super(`No finding with id ${findingId}.`);
    this.name = "UnknownFindingError";
  }
}

/**
 * Records a triage decision and appends it to the audit log.
 *
 * Both writes happen in one transaction. Half of this operation is worse than
 * none of it: a state change with no logged event is an unattributable
 * suppression, which is the exact thing the log exists to prevent.
 *
 * @param findingId - the finding's deterministic id.
 * @param state - the new state.
 * @param note - the justification. Required for anything but `untriaged`.
 * @param actor - the authenticated admin making the change. Their email is
 *   copied into the event row so the trail outlives the account.
 * @returns the stored triage record.
 * @throws {UnknownFindingError} if the finding does not exist. Checked
 *   explicitly rather than left to the foreign key, so the API can answer 404
 *   instead of 500.
 * @throws {TriageValidationError} if the note requirement is not met.
 */
export async function setTriage(
  findingId: string,
  state: TriageState,
  note: string | null,
  actor: User,
): Promise<Triage> {
  const validated = validate(state, note);

  return withTransaction(async (client) => {
    // Locked for the duration so two admins triaging the same finding at once
    // cannot interleave and log events in an order that contradicts the final
    // state.
    const finding = await client.query<{ id: string }>(
      "SELECT id FROM findings WHERE id = $1 FOR UPDATE",
      [findingId],
    );
    if (finding.rowCount === 0) throw new UnknownFindingError(findingId);

    const existing = await client.query<{ state: TriageState }>(
      "SELECT state FROM finding_triage WHERE finding_id = $1 FOR UPDATE",
      [findingId],
    );
    const previousState = existing.rows[0]?.state ?? null;

    const updated = await client.query<TriageRow>(
      `INSERT INTO finding_triage (finding_id, state, note, updated_by, updated_at)
            VALUES ($1, $2, $3, $4, now())
       ON CONFLICT (finding_id) DO UPDATE
               SET state = EXCLUDED.state,
                   note = EXCLUDED.note,
                   updated_by = EXCLUDED.updated_by,
                   updated_at = now()
         RETURNING finding_id, state, note, updated_by, updated_at`,
      [findingId, state, validated, actor.id],
    );

    await client.query(
      `INSERT INTO triage_events
            (finding_id, previous_state, new_state, note, actor_id, actor_email)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [findingId, previousState, state, validated, actor.id, actor.email],
    );

    return toTriage(updated.rows[0]!);
  });
}

/**
 * Counts open findings by triage state.
 *
 * Backs the dashboard's "N suppressed" line. Showing that number matters: a
 * risk score that quietly excludes hidden findings, with no indication that
 * anything is hidden, is a score that can be improved by suppression alone.
 */
export async function triageCounts(): Promise<Record<TriageState, number>> {
  const rows = await query<{ state: TriageState; count: string }>(
    `SELECT COALESCE(t.state, 'untriaged') AS state, COUNT(*)::text AS count
       FROM findings f
       LEFT JOIN finding_triage t ON t.finding_id = f.id
      WHERE f.status = 'open'
      GROUP BY COALESCE(t.state, 'untriaged')`,
  );

  const counts: Record<TriageState, number> = {
    untriaged: 0,
    acknowledged: 0,
    suppressed: 0,
    false_positive: 0,
  };
  for (const row of rows) counts[row.state] = Number(row.count);
  return counts;
}
