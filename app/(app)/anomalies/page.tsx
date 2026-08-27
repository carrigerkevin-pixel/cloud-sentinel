/**
 * CloudSentinel — the behavioural anomalies page, at `/anomalies`.
 *
 * What the ML layer flagged in the most recent detection run: which principals
 * behaved unusually, in which hour, and why.
 *
 * Where it sits in the architecture:
 *
 *   [ this page ] --> lib/db/anomalies.ts  latestAnomalyRun()
 *                                          anomaliesForRun()
 *                                          anomalyCountsByPrincipal()
 *
 * ## What this page is for, and how it differs from /findings
 *
 * `/findings` answers "what is configured wrongly?". This page answers "who is
 * behaving strangely?", and the two are genuinely different questions. A
 * misconfiguration is a static property of a resource that a rule can check. An
 * intrusion using stolen but *legitimate* credentials changes no configuration
 * at all — every call it makes is one the principal is authorised to make — so
 * no rule can see it. What gives it away is the pattern: the wrong hour, an
 * unfamiliar address, a sequence this principal has never performed.
 *
 * ## Three deliberate presentation choices
 *
 * **Both models are always shown.** Each row carries the Isolation Forest's
 * score and the statistical baseline's, and a badge saying which flagged it.
 * Collapsing that into one verdict would be tidier and would hide the most
 * useful thing on the page: where the two disagree. A window both models
 * flagged is a stronger signal than one only the forest isolated, and a reader
 * can see which is which instead of being handed an unexplained number.
 *
 * **Every alert carries its evidence in plain language.** An Isolation Forest
 * cannot explain itself — its score is an average path length across random
 * trees, which cannot be attributed to any single feature. So the reasons shown
 * come from the statistical model's per-feature scores. The page says so rather
 * than implying the forest reasoned that way, because the alternative is a
 * nicer story that is not true.
 *
 * **The alert budget and the concentration are shown, not buried.** A detection
 * run is only interpretable alongside how many alerts each model was allowed to
 * raise, and the per-principal breakdown exists because a run where one
 * principal accounts for most of the alerts is a run whose reader will start
 * skipping them. That is the failure mode that quietly turns a detector's real
 * recall to zero, and it should be visible on the page rather than discovered
 * after the tool has been muted.
 *
 * SECURITY: read-only, and reachable only through `app/(app)/layout.tsx`, which
 * re-verifies the session on every request before any child renders. Every
 * value shown is rendered as text by React, which escapes it — principal ARNs
 * and action names originate from the analysed log rather than from this
 * project, and must not be treated as trusted markup.
 */

import Link from "next/link";

import {
  anomaliesForRun,
  anomalyCountsByPrincipal,
  latestAnomalyRun,
} from "../../../lib/db/anomalies.ts";
import { formatAbsolute, formatAge } from "../../../lib/ui/format.ts";

// Always read live: a detection run saved from the CLI must appear on the next
// page load rather than whenever a cache happens to expire.
export const dynamic = "force-dynamic";

/**
 * Colour for an anomaly percentile.
 *
 * Banded rather than a gradient. A gradient implies the difference between 94
 * and 96 means something, and it does not — these are rank percentiles over a
 * couple of thousand windows, so neighbouring values are indistinguishable in
 * practice. Three bands say what can honestly be said: top of the list, high,
 * or merely flagged.
 */
function scoreColour(score: number): string {
  if (score >= 99.5) return "text-red-400";
  if (score >= 98) return "text-amber-300";
  return "text-zinc-300";
}

/** Short label and styling for each model badge. */
const MODEL_BADGE = {
  isolation_forest: {
    label: "forest",
    className: "border-sky-500/40 bg-sky-500/10 text-sky-300",
  },
  baseline: {
    label: "stats",
    className: "border-violet-500/40 bg-violet-500/10 text-violet-300",
  },
} as const;

export default async function AnomaliesPage() {
  const run = await latestAnomalyRun();

  if (run === null) {
    return (
      <div className="rounded-lg border border-zinc-800 bg-zinc-900/30 px-6 py-12 text-center">
        <h2 className="text-base font-medium text-zinc-200">
          No detection runs yet
        </h2>
        <p className="mx-auto mt-1 max-w-md text-sm text-zinc-500">
          The anomaly layer analyses a synthetic activity log. Generate one, run
          the detectors, then save the result.
        </p>
        <div className="mt-4 space-y-1.5">
          {["npm run ml:setup", "npm run ml:pipeline", "npm run ml:save"].map(
            (command) => (
              <code
                key={command}
                className="block rounded border border-zinc-800 bg-zinc-950 px-3 py-1.5 font-mono text-xs text-zinc-400"
              >
                {command}
              </code>
            ),
          )}
        </div>
      </div>
    );
  }

  const [anomalies, byPrincipal] = await Promise.all([
    anomaliesForRun(run.id),
    anomalyCountsByPrincipal(run.id),
  ]);

  const now = new Date();
  const both = anomalies.filter((a) => a.flaggedBy.length === 2).length;

  // The most-repeated source. This is the alert-fatigue number: if one
  // principal dominates, the reader will stop reading.
  const worst = byPrincipal[0];
  const concentration =
    worst && anomalies.length > 0 ? worst.count / anomalies.length : 0;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h1 className="text-xl font-semibold tracking-tight text-zinc-50">
          Behavioural anomalies
        </h1>
        <p className="text-sm text-zinc-500">
          run #{run.id} · {formatAge(run.detectedAt, now)} ago
        </p>
      </div>

      {/* --- Run context ------------------------------------------------- */}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {[
          {
            label: "Flagged windows",
            value: anomalies.length.toLocaleString(),
            note: `${both} by both models`,
          },
          {
            label: "Alert budget",
            value: run.alertBudget.toLocaleString(),
            note: "per model, by design",
          },
          {
            label: "Windows scored",
            value: run.windowCount.toLocaleString(),
            note: "principal x hour",
          },
          {
            label: "Events analysed",
            value: run.eventCount.toLocaleString(),
            note: `${run.logDays} days, seed ${run.logSeed}`,
          },
        ].map((card) => (
          <div
            key={card.label}
            className="rounded-lg border border-zinc-800 bg-zinc-900/30 px-4 py-3"
          >
            <div className="text-xs uppercase tracking-wide text-zinc-500">
              {card.label}
            </div>
            <div className="mt-1 text-2xl font-semibold tabular-nums text-zinc-100">
              {card.value}
            </div>
            <div className="mt-0.5 text-xs text-zinc-600">{card.note}</div>
          </div>
        ))}
      </div>

      {/*
        The alert budget deserves a sentence rather than only a number. It looks
        like a statistical parameter and is really a staffing decision, and a
        reader who takes it for an estimate of how much intrusion is present
        will misread every other figure on the page.
      */}
      <p className="rounded-lg border border-zinc-800/70 bg-zinc-900/20 px-4 py-3 text-xs leading-relaxed text-zinc-500">
        <span className="text-zinc-400">How to read this.</span> Each model was
        allowed to flag the {run.alertBudget} most unusual windows — a capacity
        choice about how much can be investigated, not an estimate of how much
        is wrong. Both models score every window, so the two columns below show
        genuine disagreement rather than one model&rsquo;s silence. Anomalies
        are observations about a past hour: unlike findings, they have no
        open-or-resolved state, because an hour cannot be un-happened.
      </p>

      {/* --- Alert concentration ------------------------------------------ */}

      {byPrincipal.length > 0 && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/30 px-4 py-3">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h2 className="text-sm font-medium text-zinc-200">
              Where the alerts landed
            </h2>
            {concentration >= 0.5 && worst && (
              <span className="text-xs text-amber-400">
                {Math.round(concentration * 100)}% of alerts are{" "}
                {worst.principalName} — a stream this repetitive gets ignored
              </span>
            )}
          </div>

          <div className="mt-3 space-y-1.5">
            {byPrincipal.map((entry) => (
              <div key={entry.principalName} className="flex items-center gap-3">
                <span className="w-56 shrink-0 truncate font-mono text-xs text-zinc-400">
                  {entry.principalName}
                </span>
                <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-zinc-800">
                  <span
                    className="block h-full rounded-full bg-zinc-500"
                    style={{
                      width: `${(entry.count / (worst?.count ?? 1)) * 100}%`,
                    }}
                  />
                </span>
                <span className="w-8 shrink-0 text-right text-xs tabular-nums text-zinc-500">
                  {entry.count}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* --- The alerts ---------------------------------------------------- */}

      <div className="overflow-x-auto rounded-lg border border-zinc-800">
        <table className="w-full min-w-[54rem] text-sm">
          <thead className="bg-zinc-900/50 text-left text-xs uppercase tracking-wide text-zinc-500">
            <tr>
              <th className="px-4 py-2.5 font-medium">Principal</th>
              <th className="px-4 py-2.5 font-medium">Window</th>
              <th className="px-4 py-2.5 font-medium">Calls</th>
              <th className="px-4 py-2.5 font-medium">Forest</th>
              <th className="px-4 py-2.5 font-medium">Stats</th>
              <th className="px-4 py-2.5 font-medium">Why</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/80">
            {anomalies.map((anomaly) => (
              <tr key={anomaly.id} className="align-top text-zinc-300">
                <td className="px-4 py-3">
                  <Link
                    href={`/anomalies/${anomaly.id}`}
                    className="font-mono text-xs text-zinc-200 underline-offset-2 hover:underline"
                  >
                    {anomaly.principalName}
                  </Link>
                  <div className="mt-1 flex gap-1">
                    {anomaly.flaggedBy.map((model) => (
                      <span
                        key={model}
                        className={`rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wide ${MODEL_BADGE[model].className}`}
                      >
                        {MODEL_BADGE[model].label}
                      </span>
                    ))}
                  </div>
                </td>

                <td className="whitespace-nowrap px-4 py-3 text-xs">
                  {formatAbsolute(anomaly.windowStart)}
                  <div className="text-zinc-600">one hour</div>
                </td>

                <td className="px-4 py-3 tabular-nums">{anomaly.eventCount}</td>

                <td
                  className={`px-4 py-3 tabular-nums ${scoreColour(anomaly.scoreIsolationForest)}`}
                >
                  {anomaly.scoreIsolationForest.toFixed(1)}
                </td>

                <td
                  className={`px-4 py-3 tabular-nums ${scoreColour(anomaly.scoreBaseline)}`}
                >
                  {anomaly.scoreBaseline.toFixed(1)}
                </td>

                <td className="px-4 py-3">
                  {anomaly.evidence.length === 0 ? (
                    // Not a gap. A window isolated on a combination of
                    // individually unremarkable features genuinely has no single
                    // feature worth naming, and saying so is more useful than
                    // inventing one.
                    <span className="text-xs text-zinc-500">
                      no single feature stands out — flagged on the combination
                    </span>
                  ) : (
                    <ul className="space-y-0.5">
                      {anomaly.evidence.map((item) => (
                        <li key={item.feature} className="text-xs text-zinc-400">
                          <span className="text-zinc-300">
                            {item.description}
                          </span>
                          <span className="ml-1.5 text-zinc-600 tabular-nums">
                            {item.zScore.toFixed(1)}σ
                          </span>
                        </li>
                      ))}
                    </ul>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="text-xs leading-relaxed text-zinc-600">
        Reasons come from the statistical model&rsquo;s per-feature scores. An
        Isolation Forest has no per-feature explanation to give — its score is an
        average path length across random trees — so these are the features that
        made the window statistically extreme, not a reconstruction of the
        forest&rsquo;s reasoning.
      </p>
    </div>
  );
}
