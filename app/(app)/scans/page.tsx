/**
 * CloudSentinel — the scan history page, at `/scans`.
 *
 * Every saved scan, newest first, with the risk score and finding counts each
 * one produced.
 *
 * Where it sits in the architecture:
 *
 *   [ this page ] --> lib/db/dashboard.ts scanHistory()
 *
 * ## What this page is for
 *
 * The overview answers "how bad is it now". This one answers "is it getting
 * better", which is a different question and the one that actually tells you
 * whether the tool is worth running. A single scan is a snapshot; a column of
 * risk scores with the new-finding count beside each is a trend.
 *
 * The `new` column is the part worth reading carefully. Fourteen findings of
 * which zero are new means a stable, unremediated environment. Fourteen of
 * which fourteen are new means something changed — either the environment or
 * the rule set — and both are worth knowing about.
 *
 * The `errors` column matters for the opposite reason: a scan with collection
 * errors did not see everything, so a *drop* in its finding count is not
 * evidence that anything was fixed. lib/db/lifecycle.ts already refuses to
 * resolve findings from such a scan; flagging it here means a person reading
 * the trend does not draw the conclusion the code declined to.
 */

import { dashboardSummary, scanHistory } from "../../../lib/db/dashboard.ts";
import {
  formatAbsolute,
  formatAge,
  riskScoreColour,
} from "../../../lib/ui/format.ts";

export const dynamic = "force-dynamic";

export default async function ScansPage() {
  const [scans, summary] = await Promise.all([
    scanHistory(50),
    dashboardSummary(),
  ]);

  const now = new Date();

  if (scans.length === 0) {
    return (
      <div className="rounded-lg border border-zinc-800 bg-zinc-900/30 px-6 py-12 text-center">
        <h2 className="text-base font-medium text-zinc-200">No scans yet</h2>
        <p className="mt-1 text-sm text-zinc-500">
          A scan is only recorded when it is saved.
        </p>
        <code className="mt-4 inline-block rounded border border-zinc-800 bg-zinc-950 px-3 py-1.5 font-mono text-xs text-zinc-400">
          npm run scan -- --save
        </code>
      </div>
    );
  }

  // The worst score in the window, used to scale the inline bars so the
  // variation between scans is visible even when every score is high.
  const worstScore = Math.max(...scans.map((scan) => scan.riskScore), 1);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h1 className="text-xl font-semibold tracking-tight text-zinc-50">
          Scan history
        </h1>
        <p className="text-sm text-zinc-500">
          {scans.length} scan{scans.length === 1 ? "" : "s"} ·{" "}
          {summary.resolved} finding{summary.resolved === 1 ? "" : "s"} resolved
          to date
        </p>
      </div>

      <div className="overflow-x-auto rounded-lg border border-zinc-800">
        <table className="w-full min-w-[46rem] text-sm">
          <thead className="bg-zinc-900/50 text-left text-xs uppercase tracking-wide text-zinc-500">
            <tr>
              <th className="px-4 py-2.5 font-medium">Scan</th>
              <th className="px-4 py-2.5 font-medium">Collected</th>
              <th className="px-4 py-2.5 font-medium">Risk</th>
              <th className="px-4 py-2.5 font-medium">Findings</th>
              <th className="px-4 py-2.5 font-medium">New</th>
              <th className="px-4 py-2.5 font-medium">Resources</th>
              <th className="px-4 py-2.5 font-medium">Errors</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/80">
            {scans.map((scan) => (
              <tr key={scan.id} className="text-zinc-300">
                <td className="px-4 py-2.5 font-mono text-xs text-zinc-500">
                  #{scan.id}
                </td>

                <td className="px-4 py-2.5">
                  {formatAbsolute(scan.collectedAt)}
                  <span className="ml-2 text-xs text-zinc-600">
                    {formatAge(scan.collectedAt, now)} ago
                  </span>
                </td>

                <td className="px-4 py-2.5">
                  <div className="flex items-center gap-2">
                    <span
                      className={`w-7 tabular-nums ${riskScoreColour(
                        scan.riskScore,
                      )}`}
                    >
                      {scan.riskScore}
                    </span>
                    <span className="h-1.5 w-20 overflow-hidden rounded-full bg-zinc-800">
                      <span
                        className="block h-full rounded-full bg-zinc-500"
                        style={{
                          width: `${(scan.riskScore / worstScore) * 100}%`,
                        }}
                      />
                    </span>
                  </div>
                </td>

                <td className="px-4 py-2.5 tabular-nums">
                  {scan.findingCount}
                </td>

                <td className="px-4 py-2.5 tabular-nums">
                  {scan.newCount > 0 ? (
                    <span className="text-amber-300">+{scan.newCount}</span>
                  ) : (
                    <span className="text-zinc-600">—</span>
                  )}
                </td>

                <td className="px-4 py-2.5 tabular-nums text-zinc-400">
                  {scan.resourcesScanned}
                  <span className="ml-1.5 text-xs text-zinc-600">
                    ({scan.resourcesClean} clean)
                  </span>
                </td>

                <td className="px-4 py-2.5 tabular-nums">
                  {scan.collectionErrors > 0 ? (
                    <span
                      className="text-amber-400"
                      title="This scan did not see the whole environment, so a lower finding count is not evidence of a fix."
                    >
                      {scan.collectionErrors}
                    </span>
                  ) : (
                    <span className="text-zinc-700">0</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="text-xs text-zinc-600">
        A scan is recorded only when run with{" "}
        <code className="font-mono text-zinc-500">npm run scan -- --save</code>.
        Scans with collection errors never resolve a finding, because an
        environment that could not be fully read cannot prove something is gone.
      </p>
    </div>
  );
}
