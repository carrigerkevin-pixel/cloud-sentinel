/**
 * CloudSentinel — the triage control.
 *
 * Lets an administrator record a decision about a finding: acknowledged,
 * suppressed, a false positive, or back to untriaged.
 *
 * Where it sits in the architecture:
 *
 *   finding detail page --> [ this component ] --PATCH--> /api/findings/<id>/triage
 *                                                             |
 *                                                             +--> finding_triage
 *                                                             +--> triage_events
 *
 * A client component: it holds form state, and after a successful change it
 * refreshes the server-rendered page around it so the audit trail and the
 * summary counts update without a manual reload.
 *
 * ## What the UI is and is not responsible for
 *
 * This component hides itself from viewers and requires a note before it will
 * submit. **Neither of those is the access control.** The route handler checks
 * the role server-side and the database enforces the note with a CHECK
 * constraint; both would reject a request crafted with `curl` that skipped this
 * form entirely. What the checks here buy is a decent experience — an
 * immediate, specific message instead of a round trip that comes back 400 —
 * and nothing more. A hidden button is not a permission.
 */

"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

// Imported from lib/types/triage.ts, NOT lib/db/triage.ts. This component is
// bundled for the browser, and lib/db/triage.ts reaches `pg` through its own
// imports — pulling the PostgreSQL driver into a client bundle fails to build,
// and should, since database code has no business being shipped to a browser.
import {
  MAX_NOTE_LENGTH,
  type TriageState,
} from "../../lib/types/triage.ts";
import { TRIAGE_LABEL } from "../../lib/ui/format.ts";

/** The states an administrator can choose, in the order they are offered. */
const CHOICES: readonly TriageState[] = [
  "untriaged",
  "acknowledged",
  "suppressed",
  "false_positive",
];

/** One-line explanations, so the difference between the two hiding states is visible. */
const EXPLANATION: Record<TriageState, string> = {
  untriaged: "Clear the decision and return this finding to the default list.",
  acknowledged: "Real, and on the list to fix. Stays visible.",
  suppressed: "Real, but accepted as a risk. Hidden from the default list.",
  false_positive:
    "The rule is wrong about this resource. Hidden, and a signal the rule needs retuning.",
};

export default function TriageControl({
  findingToken,
  currentState,
  currentNote,
  canTriage,
}: {
  /** The base64url-encoded finding id, matching the API route's path segment. */
  findingToken: string;
  currentState: TriageState;
  currentNote: string | null;
  /** False for viewers. The server enforces this regardless. */
  canTriage: boolean;
}) {
  const router = useRouter();

  const [state, setState] = useState<TriageState>(currentState);
  const [note, setNote] = useState(currentNote ?? "");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  if (!canTriage) {
    return (
      <p className="rounded-md border border-zinc-800 bg-zinc-950/40 px-3 py-2 text-xs text-zinc-500">
        Changing triage state requires an admin account. You can see every
        decision and who made it in the history below.
      </p>
    );
  }

  // Mirrors the rule in lib/db/triage.ts: anything other than `untriaged`
  // needs a justification.
  const noteRequired = state !== "untriaged";
  const noteMissing = noteRequired && note.trim().length === 0;
  const unchanged = state === currentState && note === (currentNote ?? "");

  async function save() {
    setError(null);
    setSaving(true);

    try {
      const response = await fetch(`/api/findings/${findingToken}/triage`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          state,
          note: state === "untriaged" ? null : note,
        }),
      });

      if (!response.ok) {
        const body = await response.json().catch(() => null);
        setError(body?.error?.message ?? "Could not save the decision.");
        return;
      }

      // Re-render the server components on this page so the stored state, the
      // new audit entry, and the counts in the header all come from the
      // database rather than from what this component assumed happened.
      router.refresh();
    } catch {
      setError("Could not reach the server.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        {CHOICES.map((choice) => (
          <button
            key={choice}
            type="button"
            onClick={() => setState(choice)}
            className={`rounded-md border px-2.5 py-1 text-xs transition-colors ${
              state === choice
                ? "border-sky-500/50 bg-sky-500/10 text-sky-200"
                : "border-zinc-800 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200"
            }`}
          >
            {TRIAGE_LABEL[choice]}
          </button>
        ))}
      </div>

      <p className="text-xs text-zinc-500">{EXPLANATION[state]}</p>

      {noteRequired ? (
        <div>
          <label
            htmlFor="triage-note"
            className="block text-xs uppercase tracking-wide text-zinc-500"
          >
            Justification <span className="text-zinc-600">(required)</span>
          </label>
          <textarea
            id="triage-note"
            rows={3}
            maxLength={MAX_NOTE_LENGTH}
            value={note}
            onChange={(event) => setNote(event.target.value)}
            placeholder="Why is this the right decision? This is recorded against your name and cannot be edited later."
            className="mt-1.5 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 outline-none placeholder:text-zinc-600 focus:border-sky-600"
          />
          <p className="mt-1 text-[11px] text-zinc-600">
            {note.length} / {MAX_NOTE_LENGTH}
          </p>
        </div>
      ) : null}

      {error ? (
        <p
          role="alert"
          className="rounded-md border border-red-900/50 bg-red-950/40 px-3 py-2 text-xs text-red-300"
        >
          {error}
        </p>
      ) : null}

      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={save}
          disabled={saving || noteMissing || unchanged}
          className="rounded-md bg-zinc-100 px-3 py-1.5 text-sm font-medium text-zinc-900 transition-colors hover:bg-white disabled:cursor-not-allowed disabled:opacity-40"
        >
          {saving ? "Saving…" : "Save decision"}
        </button>
        {noteMissing ? (
          <span className="text-xs text-zinc-500">
            A justification is required.
          </span>
        ) : null}
      </div>
    </div>
  );
}
