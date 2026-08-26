/**
 * CloudSentinel — the findings list, served at `/findings`.
 *
 * Every open problem, most severe and longest-standing first, with filters.
 *
 * Where it sits in the architecture:
 *
 *   [ this page ] --> lib/db/dashboard.ts listFindings()
 *          |
 *          +--> app/(app)/findings/[id]/page.tsx   one finding in detail
 *
 * A server component that reads its filters from the URL's query string rather
 * than from React state. That is a deliberate choice with three consequences
 * worth having: a filtered view is a link somebody can paste to a colleague,
 * the browser's back button behaves the way a reader expects, and there is no
 * client-side fetching or loading state to get wrong. The filter controls are a
 * plain HTML `<form method="get">`, so they work before any JavaScript has
 * loaded.
 *
 * ## Ordering
 *
 * Severity first, then oldest first. The second half is the part that only
 * exists because Phase 4 stored history: a critical finding that has been open
 * for three weeks and a critical finding first seen an hour ago are different
 * problems, and sorting the long-standing one to the top is the whole argument
 * for keeping `first_seen_at` at all.
 */

import Link from "next/link";

import { encodeFindingId } from "../../../lib/api/finding-id.ts";
import { listFindings, MAX_PAGE_SIZE } from "../../../lib/db/dashboard.ts";
import { isTriageState, type TriageState } from "../../../lib/types/triage.ts";
import {
  formatAge,
  resourceTypeLabel,
  severityBadge,
  SEVERITY_DISPLAY_ORDER,
  TRIAGE_BADGE,
  TRIAGE_LABEL,
} from "../../../lib/ui/format.ts";

export const dynamic = "force-dynamic";

/** How many findings one page shows. */
const PAGE_SIZE = 50;

/** Reads a query parameter that Next may hand over as a string or an array. */
function single(
  value: string | string[] | undefined,
): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

/** Reads a repeatable parameter, also accepting a comma-separated form. */
function many(value: string | string[] | undefined): string[] {
  const values = Array.isArray(value) ? value : value ? [value] : [];
  return values
    .flatMap((entry) => entry.split(","))
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

export default async function FindingsPage({
  searchParams,
}: {
  // A promise in Next 16, awaited below.
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;

  const statusParam = single(params.status);
  const status =
    statusParam === "resolved" || statusParam === "all" ? statusParam : "open";

  const severities = many(params.severity).filter((value) =>
    (SEVERITY_DISPLAY_ORDER as readonly string[]).includes(value),
  );
  const triageStates = many(params.triage).filter((value): value is TriageState =>
    isTriageState(value),
  );
  const search = single(params.q)?.trim() ?? "";

  const rawPage = Number(single(params.page) ?? "1");
  const page = Number.isInteger(rawPage) && rawPage > 0 ? rawPage : 1;
  const offset = Math.min((page - 1) * PAGE_SIZE, MAX_PAGE_SIZE * 1000);

  const { items, total } = await listFindings({
    status,
    severities,
    triageStates,
    search: search.length > 0 ? search : undefined,
    limit: PAGE_SIZE,
    offset,
  });

  const now = new Date();
  const lastPage = Math.max(1, Math.ceil(total / PAGE_SIZE));

  /** Rebuilds the current URL with some parameters replaced. */
  function urlWith(changes: Record<string, string | undefined>): string {
    const next = new URLSearchParams();
    if (status !== "open") next.set("status", status);
    for (const severity of severities) next.append("severity", severity);
    for (const state of triageStates) next.append("triage", state);
    if (search) next.set("q", search);

    for (const [key, value] of Object.entries(changes)) {
      next.delete(key);
      if (value !== undefined) next.set(key, value);
    }

    const query = next.toString();
    return query ? `/findings?${query}` : "/findings";
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h1 className="text-xl font-semibold tracking-tight text-zinc-50">
          Findings
        </h1>
        <p className="text-sm text-zinc-500">
          {total} {status === "open" ? "open" : status} finding
          {total === 1 ? "" : "s"}
          {triageStates.length === 0 && status !== "resolved"
            ? " (suppressed findings hidden)"
            : ""}
        </p>
      </div>

      {/* --- Filters -----------------------------------------------------
          A plain GET form: no JavaScript required, and submitting it produces
          a shareable URL rather than mutating hidden component state. */}
      <form
        method="get"
        className="flex flex-wrap items-end gap-3 rounded-lg border border-zinc-800 bg-zinc-900/30 p-4"
      >
        <label className="flex flex-col gap-1">
          <span className="text-xs uppercase tracking-wide text-zinc-500">
            Search
          </span>
          <input
            type="search"
            name="q"
            defaultValue={search}
            placeholder="title, resource name, or ARN"
            className="w-64 rounded-md border border-zinc-700 bg-zinc-950 px-2.5 py-1.5 text-sm text-zinc-100 outline-none placeholder:text-zinc-600 focus:border-sky-600"
          />
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-xs uppercase tracking-wide text-zinc-500">
            Severity
          </span>
          <select
            name="severity"
            defaultValue={severities[0] ?? ""}
            className="rounded-md border border-zinc-700 bg-zinc-950 px-2.5 py-1.5 text-sm text-zinc-100 outline-none focus:border-sky-600"
          >
            <option value="">All</option>
            {SEVERITY_DISPLAY_ORDER.map((severity) => (
              <option key={severity} value={severity}>
                {severity}
              </option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-xs uppercase tracking-wide text-zinc-500">
            Status
          </span>
          <select
            name="status"
            defaultValue={status}
            className="rounded-md border border-zinc-700 bg-zinc-950 px-2.5 py-1.5 text-sm text-zinc-100 outline-none focus:border-sky-600"
          >
            <option value="open">Open</option>
            <option value="resolved">Resolved</option>
            <option value="all">All</option>
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-xs uppercase tracking-wide text-zinc-500">
            Triage
          </span>
          <select
            name="triage"
            defaultValue={triageStates[0] ?? ""}
            className="rounded-md border border-zinc-700 bg-zinc-950 px-2.5 py-1.5 text-sm text-zinc-100 outline-none focus:border-sky-600"
          >
            <option value="">Not hidden</option>
            <option value="untriaged">Untriaged</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="suppressed">Suppressed</option>
            <option value="false_positive">False positive</option>
          </select>
        </label>

        <button
          type="submit"
          className="rounded-md bg-zinc-100 px-3 py-1.5 text-sm font-medium text-zinc-900 transition-colors hover:bg-white"
        >
          Apply
        </button>
        <Link
          href="/findings"
          className="px-2 py-1.5 text-sm text-zinc-500 transition-colors hover:text-zinc-300"
        >
          Reset
        </Link>
      </form>

      {/* --- Results ----------------------------------------------------- */}
      {items.length === 0 ? (
        <p className="rounded-lg border border-zinc-800 bg-zinc-900/30 px-6 py-12 text-center text-sm text-zinc-500">
          Nothing matches these filters.
        </p>
      ) : (
        <ul className="space-y-2">
          {items.map((finding) => (
            <li key={finding.id}>
              <Link
                href={`/findings/${encodeFindingId(finding.id)}`}
                className="block rounded-lg border border-zinc-800 bg-zinc-900/30 p-4 transition-colors hover:border-zinc-700 hover:bg-zinc-900/60"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={`rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ${severityBadge(
                      finding.severity,
                    )}`}
                  >
                    {finding.severity}
                  </span>

                  {/* An inconclusive latest verdict is called out here rather
                      than folded in with the failures. The rule could not reach
                      a verdict — that is not the same as a confirmed problem,
                      and it is certainly not a pass. */}
                  {finding.latestStatus === "inconclusive" ? (
                    <span className="rounded border border-purple-500/30 bg-purple-500/10 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-purple-300">
                      inconclusive
                    </span>
                  ) : null}

                  {finding.status === "resolved" ? (
                    <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-emerald-300">
                      resolved
                      {finding.resolutionReason === "resource_removed"
                        ? " · removed"
                        : " · fixed"}
                    </span>
                  ) : null}

                  {finding.triageState !== "untriaged" ? (
                    <span
                      className={`rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ${
                        TRIAGE_BADGE[finding.triageState]
                      }`}
                    >
                      {TRIAGE_LABEL[finding.triageState]}
                    </span>
                  ) : null}

                  <h2 className="text-sm font-medium text-zinc-100">
                    {finding.title}
                  </h2>
                </div>

                <p className="mt-1.5 break-anywhere font-mono text-xs text-zinc-500">
                  {resourceTypeLabel(finding.resourceType)} ·{" "}
                  {finding.resourceName}
                </p>

                {finding.latestDetail ? (
                  <p className="mt-2 line-clamp-2 text-xs text-zinc-400">
                    {finding.latestDetail}
                  </p>
                ) : null}

                <div className="mt-2.5 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-zinc-600">
                  {/* The age is the number that history bought. */}
                  <span>
                    open {formatAge(finding.firstSeenAt, now)}
                    {finding.status === "resolved" ? " before fixing" : ""}
                  </span>
                  <span>
                    seen in {finding.occurrenceCount} scan
                    {finding.occurrenceCount === 1 ? "" : "s"}
                  </span>
                  <span className="font-mono">{finding.benchmark}</span>
                </div>
              </Link>
            </li>
          ))}
        </ul>
      )}

      {/* --- Pagination --------------------------------------------------- */}
      {lastPage > 1 ? (
        <div className="flex items-center justify-between text-sm">
          {page > 1 ? (
            <Link
              href={urlWith({ page: page === 2 ? undefined : String(page - 1) })}
              className="text-sky-400 hover:text-sky-300"
            >
              ← Previous
            </Link>
          ) : (
            <span />
          )}
          <span className="text-zinc-600">
            Page {page} of {lastPage}
          </span>
          {page < lastPage ? (
            <Link
              href={urlWith({ page: String(page + 1) })}
              className="text-sky-400 hover:text-sky-300"
            >
              Next →
            </Link>
          ) : (
            <span />
          )}
        </div>
      ) : null}
    </div>
  );
}
