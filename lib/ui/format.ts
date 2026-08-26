/**
 * CloudSentinel — shared presentation helpers for the dashboard.
 *
 * Formatting and styling decisions that more than one page needs, kept in one
 * place so the findings list, the detail page, and the overview cannot drift
 * into showing the same fact three different ways.
 *
 * Where it sits in the architecture:
 *
 *   app/(app) pages and components --> [ this file ]
 *
 * Contains no data access and no JSX — only pure functions over values the
 * query layer already produced. That keeps it importable from both server and
 * client components without dragging a database connection into the browser
 * bundle.
 */

import type { Severity } from "../rules/types.ts";
import type { TriageState } from "../types/triage.ts";

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/**
 * Tailwind classes for a severity badge.
 *
 * The colours run red → amber → yellow → slate rather than using a single hue
 * at four opacities, because severity is the one thing a reader must be able to
 * judge at a glance across a long list. Four shades of the same colour are
 * indistinguishable when they are not adjacent on screen.
 *
 * Each entry pairs a text colour with a tinted background and a matching
 * border. The border matters for accessibility: colour alone should not be the
 * only signal, and the label inside the badge always spells the severity out.
 */
const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-500/10 text-red-300 border-red-500/30",
  high: "bg-orange-500/10 text-orange-300 border-orange-500/30",
  medium: "bg-yellow-500/10 text-yellow-200 border-yellow-500/30",
  low: "bg-slate-500/10 text-slate-300 border-slate-500/30",
};

/** Returns badge classes for a severity, falling back to the `low` styling. */
export function severityBadge(severity: string): string {
  return SEVERITY_BADGE[severity] ?? SEVERITY_BADGE.low!;
}

/** Bar/segment fill colour for a severity, used in the overview's breakdown. */
const SEVERITY_FILL: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-400",
  low: "bg-slate-500",
};

/** Returns the solid fill colour class for a severity. */
export function severityFill(severity: string): string {
  return SEVERITY_FILL[severity] ?? SEVERITY_FILL.low!;
}

/** Severities in display order, most serious first. */
export const SEVERITY_DISPLAY_ORDER: readonly Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
];

// ---------------------------------------------------------------------------
// Risk score
// ---------------------------------------------------------------------------

/**
 * Colour for the headline risk score.
 *
 * The thresholds are deliberately unforgiving at the top: anything at 70 or
 * above is red, because the score is weighted so that a single critical finding
 * already contributes 40 points. A scale that only turned red at 90 would show
 * green for an account with a world-readable bucket in it.
 */
export function riskScoreColour(score: number): string {
  if (score >= 70) return "text-red-400";
  if (score >= 40) return "text-orange-400";
  if (score >= 15) return "text-yellow-300";
  return "text-emerald-400";
}

// ---------------------------------------------------------------------------
// Triage
// ---------------------------------------------------------------------------

/** Human-readable labels for triage states. */
export const TRIAGE_LABEL: Record<TriageState, string> = {
  untriaged: "Untriaged",
  acknowledged: "Acknowledged",
  suppressed: "Suppressed",
  false_positive: "False positive",
};

/**
 * Badge classes per triage state.
 *
 * `suppressed` and `false_positive` are styled the same muted grey, because
 * both mean "hidden from the default view" and that is what a reader scanning a
 * list needs to see. The distinction between them is in the label, where it
 * belongs — it matters when reading one finding, not when scanning fifty.
 */
export const TRIAGE_BADGE: Record<TriageState, string> = {
  untriaged: "bg-zinc-700/40 text-zinc-400 border-zinc-600/40",
  acknowledged: "bg-sky-500/10 text-sky-300 border-sky-500/30",
  suppressed: "bg-zinc-600/20 text-zinc-400 border-zinc-500/30",
  false_positive: "bg-zinc-600/20 text-zinc-400 border-zinc-500/30",
};

// ---------------------------------------------------------------------------
// Dates
// ---------------------------------------------------------------------------

/**
 * Formats a date as an absolute UTC timestamp.
 *
 * UTC rather than the viewer's local zone, and stated as such. A findings report
 * is evidence about when something was observed, and a timestamp that silently
 * shifts depending on who is reading it is a poor foundation for "this bucket
 * was public from the 4th to the 11th".
 */
export function formatAbsolute(value: Date | string): string {
  const date = typeof value === "string" ? new Date(value) : value;
  return (
    date.toISOString().replace("T", " ").slice(0, 16) + " UTC"
  );
}

/** Formats just the date part, for column displays where the time is noise. */
export function formatDate(value: Date | string): string {
  const date = typeof value === "string" ? new Date(value) : value;
  return date.toISOString().slice(0, 10);
}

/**
 * Formats a date as an approximate age, e.g. `"12 days"`.
 *
 * Used beside `first_seen_at`, where the elapsed time is the point: a critical
 * finding open for three weeks is a different problem from one first seen an
 * hour ago, and the reader should not have to do the subtraction.
 *
 * @param value - the earlier date.
 * @param now - the reference point. Injectable so this is testable, and so a
 *   server-rendered page can pass one clock reading to every row rather than
 *   calling `Date.now()` per call and producing rows that disagree.
 */
export function formatAge(value: Date | string, now: Date = new Date()): string {
  const date = typeof value === "string" ? new Date(value) : value;
  const seconds = Math.max(0, (now.getTime() - date.getTime()) / 1000);

  const minutes = Math.floor(seconds / 60);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hr${hours === 1 ? "" : "s"}`;

  const days = Math.floor(hours / 24);
  if (days < 31) return `${days} day${days === 1 ? "" : "s"}`;

  const months = Math.floor(days / 30);
  if (months < 12) return `${months} mo`;

  return `${Math.floor(days / 365)} yr`;
}

// ---------------------------------------------------------------------------
// Resource types
// ---------------------------------------------------------------------------

/** Short human labels for the three resource types the collectors produce. */
export const RESOURCE_TYPE_LABEL: Record<string, string> = {
  s3_bucket: "S3 bucket",
  security_group: "Security group",
  iam_user: "IAM user",
};

/** Returns a readable label for a resource type, falling back to the raw value. */
export function resourceTypeLabel(type: string): string {
  return RESOURCE_TYPE_LABEL[type] ?? type;
}
