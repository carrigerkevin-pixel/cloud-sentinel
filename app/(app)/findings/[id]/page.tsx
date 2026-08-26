/**
 * CloudSentinel — the finding detail page, at `/findings/<token>`.
 *
 * One problem in full: what it is, why it matters, how to fix it, every scan
 * that has reported it, and the record of what anyone decided about it.
 *
 * Where it sits in the architecture:
 *
 *   findings list --> [ this page ] --> lib/db/dashboard.ts findingDetail()
 *                            |       --> lib/db/triage.ts triageHistory()
 *                            +--> app/components/TriageControl.tsx
 *
 * The `[id]` segment is a base64url token rather than the raw finding id,
 * because the real ids embed ARNs and therefore contain forward slashes — see
 * lib/api/finding-id.ts.
 *
 * ## Why the occurrence history gets this much room
 *
 * The rule engine on its own can only say what is wrong *now*; that is a
 * linter. What makes this a posture-management tool is the timeline below —
 * when the problem first appeared, whether it has been reported continuously
 * since, and whether any scan was unable to check. `first_seen_at` alone cannot
 * show a gap, and a gap is exactly where "we fixed that weeks ago" falls apart.
 */

import Link from "next/link";
import { notFound } from "next/navigation";

import {
  decodeFindingId,
  encodeFindingId,
} from "../../../../lib/api/finding-id.ts";
import { currentUser } from "../../../../lib/auth/session.ts";
import { findingDetail } from "../../../../lib/db/dashboard.ts";
import { triageHistory } from "../../../../lib/db/triage.ts";
import {
  formatAbsolute,
  formatAge,
  resourceTypeLabel,
  severityBadge,
  TRIAGE_BADGE,
  TRIAGE_LABEL,
} from "../../../../lib/ui/format.ts";
import TriageControl from "../../../components/TriageControl.tsx";

export const dynamic = "force-dynamic";

export default async function FindingDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id: token } = await params;

  const findingId = decodeFindingId(token);
  if (!findingId) notFound();

  const [finding, history, user] = await Promise.all([
    findingDetail(findingId),
    triageHistory(findingId),
    currentUser(),
  ]);

  if (!finding) notFound();

  const now = new Date();

  return (
    <div className="space-y-6">
      <Link
        href="/findings"
        className="inline-block text-xs text-zinc-500 transition-colors hover:text-zinc-300"
      >
        ← All findings
      </Link>

      {/* --- Header ------------------------------------------------------ */}
      <div>
        <div className="flex flex-wrap items-center gap-2">
          <span
            className={`rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ${severityBadge(
              finding.severity,
            )}`}
          >
            {finding.severity}
          </span>

          {finding.status === "resolved" ? (
            <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-emerald-300">
              resolved ·{" "}
              {finding.resolutionReason === "resource_removed"
                ? "resource removed"
                : "fixed"}
            </span>
          ) : (
            <span className="rounded border border-zinc-700 bg-zinc-800/40 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-zinc-300">
              open
            </span>
          )}

          {finding.triageState !== "untriaged" ? (
            <span
              className={`rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ${
                TRIAGE_BADGE[finding.triageState]
              }`}
            >
              {TRIAGE_LABEL[finding.triageState]}
            </span>
          ) : null}
        </div>

        <h1 className="mt-2 text-xl font-semibold tracking-tight text-zinc-50">
          {finding.title}
        </h1>

        {/*
          The scanner's verdict and the human's decision are presented as two
          separate facts, never merged. A suppressed finding on a still-public
          bucket reads here as "open" AND "suppressed" — which is the truth, and
          is the reason triage lives in its own table.
        */}
        {finding.status === "open" && finding.triageState !== "untriaged" ? (
          <p className="mt-2 rounded-md border border-zinc-800 bg-zinc-950/40 px-3 py-2 text-xs text-zinc-400">
            This finding is <strong className="text-zinc-200">still open</strong>{" "}
            — the most recent scan reported it. Marking it{" "}
            {TRIAGE_LABEL[finding.triageState].toLowerCase()} changes how it is
            displayed, not whether the problem exists.
          </p>
        ) : null}
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          {/* --- Evidence -------------------------------------------- */}
          <Section title="Latest evidence">
            {finding.latestStatus === "inconclusive" ? (
              <p className="mb-3 rounded-md border border-purple-500/30 bg-purple-500/10 px-3 py-2 text-xs text-purple-200">
                The most recent scan could not reach a verdict on this. That is
                not a pass — a setting could not be read, so the rule has no
                basis to clear it.
              </p>
            ) : null}
            <p className="break-anywhere text-sm text-zinc-300">
              {finding.latestDetail ?? "No evidence recorded."}
            </p>
          </Section>

          {/* --- Remediation ----------------------------------------- */}
          <Section title="Remediation">
            <p className="break-anywhere whitespace-pre-wrap font-mono text-xs text-zinc-300">
              {finding.remediation}
            </p>
          </Section>

          {/* --- Occurrence history ---------------------------------- */}
          <Section
            title={`Reported in ${finding.occurrences.length} scan${
              finding.occurrences.length === 1 ? "" : "s"
            }`}
          >
            <ol className="space-y-3">
              {finding.occurrences.map((occurrence) => (
                <li
                  key={occurrence.scanId}
                  className="border-l-2 border-zinc-800 pl-3"
                >
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <span className="text-zinc-400">
                      {formatAbsolute(occurrence.detectedAt)}
                    </span>
                    <span className="text-zinc-600">
                      scan #{occurrence.scanId}
                    </span>
                    {occurrence.status === "inconclusive" ? (
                      <span className="rounded border border-purple-500/30 bg-purple-500/10 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-purple-300">
                        inconclusive
                      </span>
                    ) : null}
                    {/* Severity is stored per occurrence as well as on the
                        finding, because a rule may weigh the same problem
                        differently as conditions change. Showing it here is
                        what makes that movement visible. */}
                    {occurrence.severity !== finding.severity ? (
                      <span className="text-[10px] uppercase tracking-wide text-zinc-500">
                        was {occurrence.severity}
                      </span>
                    ) : null}
                  </div>
                  <p className="mt-1 break-anywhere text-xs text-zinc-500">
                    {occurrence.detail}
                  </p>
                </li>
              ))}
            </ol>
          </Section>
        </div>

        {/* --- Sidebar ------------------------------------------------- */}
        <div className="space-y-6">
          <Section title="Resource">
            <dl className="space-y-2 text-xs">
              <Field label="Name" value={finding.resourceName} mono />
              <Field
                label="Type"
                value={resourceTypeLabel(finding.resourceType)}
              />
              <Field label="Region" value={finding.region} />
              <Field label="Identifier" value={finding.resourceId} mono />
            </dl>
          </Section>

          <Section title="Lifecycle">
            <dl className="space-y-2 text-xs">
              <Field
                label="First seen"
                value={`${formatAbsolute(finding.firstSeenAt)} (${formatAge(
                  finding.firstSeenAt,
                  now,
                )} ago)`}
              />
              <Field
                label="Last seen"
                value={formatAbsolute(finding.lastSeenAt)}
              />
              {finding.resolvedAt ? (
                <Field
                  label="Resolved"
                  value={formatAbsolute(finding.resolvedAt)}
                />
              ) : null}
            </dl>
          </Section>

          <Section title="Rule">
            <dl className="space-y-2 text-xs">
              <Field label="Rule id" value={finding.ruleId} mono />
              <Field label="Benchmark" value={finding.benchmark} />
              <Field label="Finding id" value={finding.id} mono />
            </dl>
            <Link
              href={`/findings?rule=${encodeURIComponent(finding.ruleId)}`}
              className="mt-3 inline-block text-xs text-sky-400 hover:text-sky-300"
            >
              Other findings from this rule →
            </Link>
          </Section>
        </div>
      </div>

      {/* --- Triage --------------------------------------------------- */}
      <Section title="Triage">
        <TriageControl
          findingToken={encodeFindingId(finding.id)}
          currentState={finding.triageState}
          currentNote={finding.triageNote}
          canTriage={user?.role === "admin"}
        />

        {history.length > 0 ? (
          <div className="mt-6 border-t border-zinc-800 pt-4">
            <h3 className="text-xs uppercase tracking-wide text-zinc-500">
              Decision history
            </h3>
            <ol className="mt-3 space-y-3">
              {history.map((event) => (
                <li
                  key={event.id}
                  className="border-l-2 border-zinc-800 pl-3 text-xs"
                >
                  <div className="flex flex-wrap items-center gap-x-2 text-zinc-400">
                    <span className="text-zinc-300">
                      {event.previousState
                        ? `${TRIAGE_LABEL[event.previousState]} → ${
                            TRIAGE_LABEL[event.newState]
                          }`
                        : TRIAGE_LABEL[event.newState]}
                    </span>
                    {/* The actor's email comes from triage_events.actor_email,
                        stored as text rather than joined from `users`, so it
                        survives the account being deleted. */}
                    <span className="text-zinc-600">by {event.actorEmail}</span>
                    <span className="text-zinc-600">
                      {formatAbsolute(event.createdAt)}
                    </span>
                  </div>
                  {event.note ? (
                    <p className="mt-1 break-anywhere text-zinc-500">
                      {event.note}
                    </p>
                  ) : null}
                </li>
              ))}
            </ol>
          </div>
        ) : null}
      </Section>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Small presentational pieces
// ---------------------------------------------------------------------------

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-lg border border-zinc-800 bg-zinc-900/30 p-5">
      <h2 className="mb-3 text-sm font-medium text-zinc-300">{title}</h2>
      {children}
    </section>
  );
}

/** A labelled value in a definition list. `mono` for identifiers. */
function Field({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div>
      <dt className="text-zinc-600">{label}</dt>
      <dd
        className={`break-anywhere text-zinc-300 ${mono ? "font-mono" : ""}`}
      >
        {value}
      </dd>
    </div>
  );
}
