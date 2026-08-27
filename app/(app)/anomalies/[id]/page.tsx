/**
 * CloudSentinel — anomaly detail page, at `/anomalies/<id>`.
 *
 * Everything the detectors saw about one flagged principal-hour: both scores,
 * the plain-language evidence, the complete feature vector, the actions
 * involved, and a sample of the underlying event ids.
 *
 * Where it sits in the architecture:
 *
 *   /anomalies --> [ this page ] --> lib/db/anomalies.ts anomalyById()
 *
 * ## Why the whole feature vector is on the page
 *
 * The list view shows the top three reasons, which is the right amount for
 * triage. This page shows all fourteen features, including the thirteen that
 * were unremarkable, and that is deliberate.
 *
 * An analyst deciding whether an alert is real needs to know what *did not*
 * happen as much as what did. "Volume was 20x normal" is alarming; "volume was
 * 20x normal, from the usual address, in the usual region, with no failures and
 * no permission changes" is a bulk export somebody scheduled. Showing only the
 * features that fired would present every alert as maximally suspicious, which
 * is how a tool teaches its users to distrust it.
 *
 * It also makes the model auditable. Every number here is one the detector
 * actually used, so a disputed alert can be argued about concretely rather than
 * on the authority of a score.
 *
 * SECURITY: read-only, behind the session guard in `app/(app)/layout.tsx`. The
 * `id` in the URL is parsed as an integer and passed as a query parameter, so a
 * hand-edited URL produces a 404 rather than reaching the database as text. All
 * displayed values — ARNs, action names, event ids — come from the analysed log
 * rather than from this project, and are rendered as text by React.
 */

import Link from "next/link";
import { notFound } from "next/navigation";

import { anomalyById } from "../../../../lib/db/anomalies.ts";
import { formatAbsolute } from "../../../../lib/ui/format.ts";

export const dynamic = "force-dynamic";

/** Label and styling for each model. Mirrors the list page. */
const MODEL_BADGE = {
  isolation_forest: {
    label: "Isolation Forest",
    className: "border-sky-500/40 bg-sky-500/10 text-sky-300",
  },
  baseline: {
    label: "Statistical baseline",
    className: "border-violet-500/40 bg-violet-500/10 text-violet-300",
  },
} as const;

/**
 * Human-readable names for the feature columns.
 *
 * Duplicated from `ml/features.py`'s `FEATURE_DESCRIPTIONS` rather than read
 * from the stored row, because the stored `features` map holds only values. The
 * evidence entries carry their own descriptions; this table covers the features
 * that were *not* extreme enough to become evidence and therefore arrive
 * without one.
 *
 * A feature not listed here still renders — under its raw name — so adding a
 * feature in Python cannot break this page.
 */
const FEATURE_LABELS: Record<string, string> = {
  event_count: "API calls in the hour",
  volume_ratio: "Volume vs. this hour of day",
  distinct_actions: "Distinct API actions",
  unseen_action_rate: "Calls using never-before-seen actions",
  error_rate: "Failure rate",
  error_excess: "Failure rate above normal",
  write_ratio: "Calls that modified state",
  distinct_ips: "Distinct source addresses",
  unseen_ip_rate: "Calls from unseen address ranges",
  unseen_region_rate: "Calls from unseen regions",
  hour_rarity: "Unusualness of this hour for this principal",
  sensitive_count: "Permission or credential changes",
  sensitive_novelty: "Sensitive calls vs. history of making them",
  distinct_resources: "Distinct resources touched",
};

export default async function AnomalyDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;

  // Parsed strictly. `Number("12abc")` is NaN and `parseInt("12abc")` is 12 —
  // the second would happily accept a malformed URL, so the strict form is used
  // and anything non-numeric becomes a 404.
  const anomalyId = Number(id);
  if (!Number.isInteger(anomalyId) || anomalyId < 1) notFound();

  const anomaly = await anomalyById(anomalyId);
  if (anomaly === null) notFound();

  const featureNames = Object.keys(anomaly.features).sort();
  const evidenceFeatures = new Set(anomaly.evidence.map((item) => item.feature));

  return (
    <div className="space-y-6">
      <div>
        <Link
          href="/anomalies"
          className="text-xs text-zinc-500 underline-offset-2 hover:text-zinc-300 hover:underline"
        >
          ← Back to anomalies
        </Link>

        <h1 className="mt-2 font-mono text-lg font-semibold tracking-tight text-zinc-50">
          {anomaly.principalName}
        </h1>
        <p className="mt-0.5 break-all font-mono text-xs text-zinc-600">
          {anomaly.principalArn}
        </p>
      </div>

      {/* --- Headline ------------------------------------------------------ */}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {[
          {
            label: "Window",
            value: formatAbsolute(anomaly.windowStart),
            note: "one hour, UTC",
          },
          {
            label: "API calls",
            value: anomaly.eventCount.toLocaleString(),
            note: "in this window",
          },
          {
            label: "Isolation Forest",
            value: anomaly.scoreIsolationForest.toFixed(1),
            note: "percentile of all windows",
          },
          {
            label: "Statistical baseline",
            value: anomaly.scoreBaseline.toFixed(1),
            note: "percentile of all windows",
          },
        ].map((card) => (
          <div
            key={card.label}
            className="rounded-lg border border-zinc-800 bg-zinc-900/30 px-4 py-3"
          >
            <div className="text-xs uppercase tracking-wide text-zinc-500">
              {card.label}
            </div>
            <div className="mt-1 text-xl font-semibold tabular-nums text-zinc-100">
              {card.value}
            </div>
            <div className="mt-0.5 text-xs text-zinc-600">{card.note}</div>
          </div>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-zinc-500">Flagged by</span>
        {anomaly.flaggedBy.map((model) => (
          <span
            key={model}
            className={`rounded border px-2 py-0.5 text-xs ${MODEL_BADGE[model].className}`}
          >
            {MODEL_BADGE[model].label}
          </span>
        ))}
        {anomaly.flaggedBy.length === 1 && (
          <span className="text-xs text-zinc-600">
            — the other model scored this window but did not rank it inside its
            alert budget
          </span>
        )}
      </div>

      {/* --- Evidence ------------------------------------------------------ */}

      <section className="rounded-lg border border-zinc-800 bg-zinc-900/30 px-4 py-3">
        <h2 className="text-sm font-medium text-zinc-200">
          Why this hour looks unusual
        </h2>

        {anomaly.evidence.length === 0 ? (
          <p className="mt-2 text-sm text-zinc-500">
            No single feature was extreme. This window was flagged on the
            combination of several mildly unusual features at once — which is
            the case the Isolation Forest exists to catch and the statistical
            model cannot express. The full vector below is the whole picture.
          </p>
        ) : (
          <ul className="mt-2 space-y-2">
            {anomaly.evidence.map((item) => (
              <li key={item.feature} className="flex items-baseline gap-3">
                <span className="w-14 shrink-0 text-right font-mono text-xs tabular-nums text-amber-300">
                  {item.zScore.toFixed(1)}σ
                </span>
                <span className="text-sm text-zinc-300">
                  {item.description}
                  <span className="ml-2 font-mono text-xs text-zinc-600">
                    {item.feature}
                  </span>
                </span>
              </li>
            ))}
          </ul>
        )}

        <p className="mt-3 border-t border-zinc-800/80 pt-2 text-xs leading-relaxed text-zinc-600">
          Measured in robust standard deviations from this principal&rsquo;s own
          median, capped at 25. These come from the statistical model even when
          the Isolation Forest raised the alert: a forest score is an average
          path length across random trees and cannot be attributed to any one
          feature, so this is supporting evidence rather than the forest&rsquo;s
          internal reasoning.
        </p>
      </section>

      {/* --- Full feature vector ------------------------------------------- */}

      <section className="rounded-lg border border-zinc-800">
        <div className="border-b border-zinc-800 px-4 py-2.5">
          <h2 className="text-sm font-medium text-zinc-200">
            Every measured feature
          </h2>
          <p className="mt-0.5 text-xs text-zinc-600">
            Including the ones that were ordinary — what did not happen matters
            as much as what did.
          </p>
        </div>

        <div className="divide-y divide-zinc-800/80">
          {featureNames.map((name) => (
            <div
              key={name}
              className="flex items-baseline gap-3 px-4 py-2 text-sm"
            >
              <span className="flex-1 text-zinc-400">
                {FEATURE_LABELS[name] ?? name}
                <span className="ml-2 font-mono text-xs text-zinc-600">
                  {name}
                </span>
              </span>
              <span
                className={`w-24 text-right font-mono text-xs tabular-nums ${
                  evidenceFeatures.has(name) ? "text-amber-300" : "text-zinc-500"
                }`}
              >
                {anomaly.features[name]?.toFixed(3)}
              </span>
            </div>
          ))}
        </div>
      </section>

      {/* --- Context -------------------------------------------------------- */}

      <div className="grid gap-3 lg:grid-cols-2">
        <section className="rounded-lg border border-zinc-800 bg-zinc-900/30 px-4 py-3">
          <h2 className="text-sm font-medium text-zinc-200">
            Most common actions
          </h2>
          <ul className="mt-2 space-y-1">
            {anomaly.sampleActions.map((action) => (
              <li key={action} className="font-mono text-xs text-zinc-400">
                {action}
              </li>
            ))}
          </ul>
        </section>

        <section className="rounded-lg border border-zinc-800 bg-zinc-900/30 px-4 py-3">
          <h2 className="text-sm font-medium text-zinc-200">Event ids</h2>
          <p className="mt-0.5 text-xs text-zinc-600">
            {anomaly.sampleEventIds.length} of {anomaly.eventCount} shown — enough
            to find the window in the raw log.
          </p>
          <div className="mt-2 max-h-40 overflow-y-auto">
            <ul className="space-y-0.5">
              {anomaly.sampleEventIds.map((eventId) => (
                <li key={eventId} className="font-mono text-[11px] text-zinc-500">
                  {eventId}
                </li>
              ))}
            </ul>
          </div>
        </section>
      </div>
    </div>
  );
}
