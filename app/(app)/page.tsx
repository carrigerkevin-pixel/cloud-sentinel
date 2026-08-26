/**
 * CloudSentinel — the overview page, served at `/`.
 *
 * The dashboard's headline: current risk score, what is open and how badly,
 * what is hidden by triage, and the most recent scans.
 *
 * Where it sits in the architecture:
 *
 *   [ this page ] --> lib/db/dashboard.ts dashboardSummary(), scanHistory()
 *
 * A server component. It queries Postgres directly rather than fetching its own
 * `/api/summary` endpoint — that route exists for client-side callers, and
 * having the page make an HTTP request to itself would add a round trip to
 * every render for no benefit. Both paths run the same query function, so they
 * cannot disagree.
 *
 * ## The design decision worth defending here
 *
 * The page shows **two** severity counts, side by side, whenever anything has
 * been suppressed: what is currently displayed, and the true total.
 *
 * The temptation with a risk dashboard is to show one number that goes down
 * when you triage things, because that feels like progress. It is exactly the
 * wrong incentive — it means the headline figure can be improved by clicking
 * "suppress" rather than by fixing anything. So the risk score and the totals
 * here always reflect every open finding, and the amount hidden is stated
 * plainly rather than being something a reader has to go looking for.
 */

import Link from "next/link";

import { dashboardSummary, scanHistory } from "../../lib/db/dashboard.ts";
import {
  formatAbsolute,
  formatAge,
  riskScoreColour,
  severityBadge,
  severityFill,
  SEVERITY_DISPLAY_ORDER,
} from "../../lib/ui/format.ts";

/**
 * Rendered fresh on every request.
 *
 * Findings data changes whenever a scan is saved or somebody triages something,
 * and a cached security dashboard showing last week's posture is worse than no
 * dashboard — it is confidently wrong.
 */
export const dynamic = "force-dynamic";

export default async function OverviewPage() {
  const [summary, scans] = await Promise.all([
    dashboardSummary(),
    scanHistory(5),
  ]);

  const { latestScan } = summary;

  // Nothing has ever been saved. Rather than rendering a page full of zeroes
  // that looks like a clean environment, say what is actually true and give the
  // command that fixes it.
  if (!latestScan) {
    return (
      <EmptyState
        title="No scans yet"
        body="Save a scan to populate the dashboard."
        command="npm run scan -- --save"
      />
    );
  }

  const totalOpen = SEVERITY_DISPLAY_ORDER.reduce(
    (sum, severity) => sum + summary.totalBySeverity[severity],
    0,
  );
  const hiddenCount = summary.hidden.suppressed + summary.hidden.falsePositive;
  const now = new Date();

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-zinc-50">
          Overview
        </h1>
        <p className="mt-1 text-sm text-zinc-500">
          Scan #{latestScan.id} · collected {formatAbsolute(latestScan.collectedAt)} ·{" "}
          <span className="font-mono text-zinc-600">{latestScan.endpoint}</span>{" "}
          <span className="text-zinc-600">({latestScan.region})</span>
        </p>
      </div>

      {/*
        A scan with collection errors did not see the whole environment, so its
        "no findings here" is not a clean bill of health. The rule engine already
        refuses to resolve findings from such a scan (lib/db/lifecycle.ts); this
        makes the same fact visible to whoever is reading the numbers.
      */}
      {latestScan.collectionErrors > 0 ? (
        <div className="rounded-lg border border-amber-900/50 bg-amber-950/30 px-4 py-3 text-sm text-amber-200">
          <strong className="font-medium">
            The most recent scan had {latestScan.collectionErrors} collection{" "}
            {latestScan.collectionErrors === 1 ? "error" : "errors"}.
          </strong>{" "}
          It did not see the whole environment, so these counts are a floor, not
          a total. No finding was resolved on the basis of this scan.
        </div>
      ) : null}

      {/* --- Headline figures ------------------------------------------- */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card label="Risk score">
          <span
            className={`text-3xl font-semibold tabular-nums ${riskScoreColour(
              latestScan.riskScore,
            )}`}
          >
            {latestScan.riskScore}
          </span>
          <span className="ml-1 text-sm text-zinc-600">/ 100</span>
        </Card>

        <Card label="Open findings">
          <span className="text-3xl font-semibold tabular-nums text-zinc-100">
            {totalOpen}
          </span>
          {hiddenCount > 0 ? (
            <span className="ml-2 text-xs text-zinc-500">
              {hiddenCount} hidden by triage
            </span>
          ) : null}
        </Card>

        <Card label="Resources scanned">
          <span className="text-3xl font-semibold tabular-nums text-zinc-100">
            {latestScan.resourcesScanned}
          </span>
          <span className="ml-2 text-xs text-zinc-500">
            {latestScan.resourcesClean} clean
          </span>
        </Card>

        <Card label="Resolved to date">
          <span className="text-3xl font-semibold tabular-nums text-emerald-400">
            {summary.resolved}
          </span>
          {summary.newInLatestScan > 0 ? (
            <span className="ml-2 text-xs text-amber-300">
              {summary.newInLatestScan} new this scan
            </span>
          ) : null}
        </Card>
      </div>

      {/* --- Severity breakdown ------------------------------------------ */}
      <section className="rounded-lg border border-zinc-800 bg-zinc-900/30 p-5">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h2 className="text-sm font-medium text-zinc-300">By severity</h2>
          {hiddenCount > 0 ? (
            <p className="text-xs text-zinc-500">
              Totals include {hiddenCount} finding
              {hiddenCount === 1 ? "" : "s"} hidden from the default list.
            </p>
          ) : null}
        </div>

        {/* A single proportional bar reads faster than four numbers when the
            question is "how bad is this", which is the question the overview
            exists to answer. The numbers are still below it for the reader who
            wants them. */}
        <div className="mt-4 flex h-2 w-full overflow-hidden rounded-full bg-zinc-800">
          {SEVERITY_DISPLAY_ORDER.map((severity) => {
            const count = summary.totalBySeverity[severity];
            if (count === 0) return null;
            return (
              <div
                key={severity}
                className={severityFill(severity)}
                style={{ width: `${(count / totalOpen) * 100}%` }}
                title={`${count} ${severity}`}
              />
            );
          })}
        </div>

        <div className="mt-4 grid gap-3 sm:grid-cols-4">
          {SEVERITY_DISPLAY_ORDER.map((severity) => {
            const total = summary.totalBySeverity[severity];
            const shown = summary.openBySeverity[severity];
            return (
              <Link
                key={severity}
                href={`/findings?severity=${severity}`}
                className="rounded-md border border-zinc-800 px-3 py-2 transition-colors hover:border-zinc-700 hover:bg-zinc-800/40"
              >
                <span
                  className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ${severityBadge(
                    severity,
                  )}`}
                >
                  {severity}
                </span>
                <div className="mt-1.5 text-2xl font-semibold tabular-nums text-zinc-100">
                  {total}
                </div>
                {total !== shown ? (
                  <div className="text-[11px] text-zinc-500">
                    {shown} shown, {total - shown} hidden
                  </div>
                ) : null}
              </Link>
            );
          })}
        </div>

        {summary.inconclusive > 0 ? (
          // Inconclusive is never rounded down to a pass anywhere else in the
          // system, so it must not quietly vanish here either.
          <p className="mt-4 rounded-md border border-zinc-800 bg-zinc-950/40 px-3 py-2 text-xs text-zinc-400">
            <strong className="font-medium text-zinc-300">
              {summary.inconclusive} inconclusive
            </strong>{" "}
            — the rule could not reach a verdict because a setting could not be
            read. These are not passes, and are counted above.
          </p>
        ) : null}
      </section>

      {/* --- Recent scans ------------------------------------------------ */}
      <section>
        <div className="flex items-baseline justify-between">
          <h2 className="text-sm font-medium text-zinc-300">Recent scans</h2>
          <Link href="/scans" className="text-xs text-sky-400 hover:text-sky-300">
            All scans →
          </Link>
        </div>

        <div className="mt-3 overflow-hidden rounded-lg border border-zinc-800">
          <table className="w-full text-sm">
            <thead className="bg-zinc-900/50 text-left text-xs uppercase tracking-wide text-zinc-500">
              <tr>
                <th className="px-4 py-2 font-medium">Collected</th>
                <th className="px-4 py-2 font-medium">Risk</th>
                <th className="px-4 py-2 font-medium">Findings</th>
                <th className="px-4 py-2 font-medium">New</th>
                <th className="px-4 py-2 font-medium">Resources</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/80">
              {scans.map((scan) => (
                <tr key={scan.id} className="text-zinc-300">
                  <td className="px-4 py-2">
                    {formatAbsolute(scan.collectedAt)}
                    <span className="ml-2 text-xs text-zinc-600">
                      {formatAge(scan.collectedAt, now)} ago
                    </span>
                  </td>
                  <td
                    className={`px-4 py-2 tabular-nums ${riskScoreColour(
                      scan.riskScore,
                    )}`}
                  >
                    {scan.riskScore}
                  </td>
                  <td className="px-4 py-2 tabular-nums">{scan.findingCount}</td>
                  <td className="px-4 py-2 tabular-nums">
                    {scan.newCount > 0 ? (
                      <span className="text-amber-300">+{scan.newCount}</span>
                    ) : (
                      <span className="text-zinc-600">—</span>
                    )}
                  </td>
                  <td className="px-4 py-2 tabular-nums text-zinc-500">
                    {scan.resourcesScanned}
                    {scan.collectionErrors > 0 ? (
                      <span className="ml-2 text-amber-400">
                        {scan.collectionErrors} err
                      </span>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Small presentational pieces
// ---------------------------------------------------------------------------

/** A headline figure with its label. */
function Card({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/30 p-4">
      <div className="text-xs uppercase tracking-wide text-zinc-500">
        {label}
      </div>
      <div className="mt-1.5 flex items-baseline">{children}</div>
    </div>
  );
}

/** Shown when there is no data yet, with the command that produces some. */
function EmptyState({
  title,
  body,
  command,
}: {
  title: string;
  body: string;
  command: string;
}) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/30 px-6 py-12 text-center">
      <h2 className="text-base font-medium text-zinc-200">{title}</h2>
      <p className="mt-1 text-sm text-zinc-500">{body}</p>
      <code className="mt-4 inline-block rounded border border-zinc-800 bg-zinc-950 px-3 py-1.5 font-mono text-xs text-zinc-400">
        {command}
      </code>
    </div>
  );
}
