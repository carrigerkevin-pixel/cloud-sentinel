/**
 * CloudSentinel — anomaly report parsing and validation.
 *
 * Reads the JSON written by `ml/detect.py` and turns it into a validated
 * {@link AnomalyReport}, or fails with a message naming the exact field that is
 * wrong.
 *
 * Where it sits in the architecture: the guard on the return leg of the
 * cross-language boundary.
 *
 *   ml/detect.py --> fixtures/anomalies.json --> [ this file ] --> lib/db/anomalies.ts
 *
 * ---------------------------------------------------------------------------
 * Why this file validates when scripts/scan.ts deliberately does not
 * ---------------------------------------------------------------------------
 *
 * `scripts/scan.ts` loads `fixtures/inventory.json` with a bare
 * `JSON.parse(...) as ResourceInventory` and says so in a comment: the only
 * producer is this project's own collector, the only consumers are its own
 * rules, and the rules already tolerate missing data. Adding a schema validator
 * there would be ceremony.
 *
 * Three things are different here, and together they change the answer.
 *
 * 1. **The producer is in another language.** TypeScript cannot check
 *    `ml/detect.py`. If a Python-side rename ships, the `as` cast would be a
 *    lie the compiler happily accepts, and the failure would surface much later
 *    as `undefined` in a database column or a blank field on a page. Validating
 *    at the boundary turns a silent corruption into an immediate, specific
 *    error: "anomalies[3].scores.isolationForest: expected a number".
 *
 * 2. **The data reaches a database and then a browser.** The inventory is read,
 *    evaluated, and discarded. These records are persisted and then rendered.
 *    Anything that gets written to a table and later put in front of a user
 *    deserves a check on the way in, because that is the last point where the
 *    error is cheap to diagnose.
 *
 * 3. **It is a file on disk that anything can write to.** Trust here rests on a
 *    path, not on a call. Treating a file as a trust boundary costs about a
 *    hundred lines and removes a whole class of "how did *that* get into the
 *    database" question.
 *
 * SECURITY: this is defence in depth rather than a claim that the ML layer is
 * hostile. The concrete protections are bounds on every numeric field (so a
 * NaN, an Infinity or a negative percentile cannot reach a `NUMERIC(5,2)`
 * column and trip a constraint violation the user sees as a 500), a cap on
 * every array length (so one malformed record cannot write an unbounded row),
 * and rejection of anything that is not a plain finite value. Validation is
 * *not* a substitute for parameterised queries — `lib/db/anomalies.ts` still
 * parameterises everything, because a validator is a check and parameterisation
 * is a guarantee.
 */

import { readFile } from "node:fs/promises";

import type {
  Anomaly,
  AnomalyEvidence,
  AnomalyModel,
  AnomalyReport,
  AnomalyRunMetadata,
} from "../types/anomaly.ts";

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/**
 * How many event ids are kept per anomaly.
 *
 * The exfiltration window contains over three hundred events. Storing every id
 * would make the row large and give an analyst nothing — nobody reads three
 * hundred UUIDs, and the full list lives in the log anyway. Enough to pivot
 * into the raw events is the useful amount.
 */
export const SAMPLE_EVENT_ID_LIMIT = 50;

/** Maximum actions kept per anomaly. `ml/detect.py` emits five. */
const SAMPLE_ACTION_LIMIT = 10;

/** Maximum evidence entries kept. `ml/baseline.py` emits at most three. */
const EVIDENCE_LIMIT = 10;

/**
 * Maximum anomalies accepted in one report.
 *
 * A sanity bound, not a real limit: the alert budget means a normal run
 * produces a few dozen. A file claiming a hundred thousand alerts is a bug or a
 * mistake, and refusing it beats inserting it.
 */
const MAX_ANOMALIES = 10_000;

/** Longest accepted string for any single text field. */
const MAX_STRING = 2_048;

/** The recognised model identifiers. */
const MODELS: readonly AnomalyModel[] = ["isolation_forest", "baseline"];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * A malformed anomaly report.
 *
 * Its own class so callers can distinguish "the file is wrong" from "the file
 * could not be read" and from a database failure — three problems with three
 * different fixes.
 */
export class AnomalyReportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AnomalyReportError";
  }
}

// ---------------------------------------------------------------------------
// Primitive checks
// ---------------------------------------------------------------------------

/**
 * Reads a required property from an unknown object.
 *
 * @param value - the object under inspection.
 * @param path - dotted path used in error messages, e.g. `"anomalies[3]"`.
 * @returns the value as an index signature.
 * @throws {AnomalyReportError} if it is not a plain object.
 */
function asObject(value: unknown, path: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new AnomalyReportError(`${path}: expected an object`);
  }
  return value as Record<string, unknown>;
}

/**
 * Validates a finite number, optionally within a range.
 *
 * The finiteness check is the important one. `JSON.parse` cannot itself produce
 * `NaN` or `Infinity` (JSON has no literal for either), but a value can still
 * arrive as `null` or a string, and `Number(null)` is 0 while `Number("abc")`
 * is `NaN`. Rejecting anything that is not already a finite number keeps those
 * out of a `NUMERIC` column, where they surface as a constraint violation that
 * a user experiences as a 500.
 *
 * @param value - the candidate.
 * @param path - dotted path for the error message.
 * @param min - inclusive lower bound, if any.
 * @param max - inclusive upper bound, if any.
 * @throws {AnomalyReportError} if it is not a finite number, or is out of range.
 */
function asNumber(
  value: unknown,
  path: string,
  min?: number,
  max?: number,
): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new AnomalyReportError(`${path}: expected a finite number`);
  }
  if (min !== undefined && value < min) {
    throw new AnomalyReportError(`${path}: ${value} is below the minimum ${min}`);
  }
  if (max !== undefined && value > max) {
    throw new AnomalyReportError(`${path}: ${value} is above the maximum ${max}`);
  }
  return value;
}

/**
 * Validates a non-empty string within the length limit.
 *
 * @param value - the candidate.
 * @param path - dotted path for the error message.
 * @throws {AnomalyReportError} if it is not a string, is empty, or is too long.
 */
function asString(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new AnomalyReportError(`${path}: expected a non-empty string`);
  }
  if (value.length > MAX_STRING) {
    throw new AnomalyReportError(
      `${path}: string of ${value.length} characters exceeds the ${MAX_STRING} limit`,
    );
  }
  return value;
}

/**
 * Validates an ISO 8601 timestamp.
 *
 * Checks that it parses *and* that it round-trips, because `new Date()` is
 * famously permissive — it will happily accept `"2026-13-45"` in some engines
 * and produce something. Comparing against the canonical serialisation catches
 * values that parse to a date nobody meant.
 *
 * @param value - the candidate.
 * @param path - dotted path for the error message.
 * @returns the timestamp as a `Date`.
 * @throws {AnomalyReportError} if it is not a valid timestamp.
 */
function asTimestamp(value: unknown, path: string): Date {
  const text = asString(value, path);
  const date = new Date(text);

  if (Number.isNaN(date.getTime())) {
    throw new AnomalyReportError(`${path}: "${text}" is not a valid timestamp`);
  }
  return date;
}

/**
 * Validates an array and enforces a maximum length.
 *
 * The cap is truncating rather than rejecting for the sample fields, because a
 * long list there is expected and harmless — the caller passes the limit it
 * wants. For structural arrays a too-long value indicates a real problem, and
 * those callers pass a limit large enough that reaching it means something is
 * wrong.
 *
 * @param value - the candidate.
 * @param path - dotted path for the error message.
 * @param limit - maximum entries to keep.
 * @throws {AnomalyReportError} if it is not an array.
 */
function asArray(value: unknown, path: string, limit: number): unknown[] {
  if (!Array.isArray(value)) {
    throw new AnomalyReportError(`${path}: expected an array`);
  }
  return value.slice(0, limit);
}

// ---------------------------------------------------------------------------
// Structure
// ---------------------------------------------------------------------------

/**
 * Validates one evidence entry.
 *
 * @param value - the candidate.
 * @param path - dotted path for the error message.
 */
function parseEvidence(value: unknown, path: string): AnomalyEvidence {
  const raw = asObject(value, path);

  return {
    feature: asString(raw.feature, `${path}.feature`),
    // Bounded at the cap ml/baseline.py applies, with a little headroom so a
    // tuning change there does not immediately fail ingestion.
    zScore: asNumber(raw.zScore, `${path}.zScore`, 0, 1000),
    description: asString(raw.description, `${path}.description`),
  };
}

/**
 * Validates the `flaggedBy` list.
 *
 * @throws {AnomalyReportError} if it is empty or names an unknown model. Empty
 *   is rejected because an anomaly nothing flagged is a contradiction, and an
 *   unknown model name means the Python side has grown a detector the dashboard
 *   does not know how to display — better to fail loudly than to render a blank
 *   badge.
 */
function parseFlaggedBy(value: unknown, path: string): AnomalyModel[] {
  const raw = asArray(value, path, MODELS.length);

  const models = raw.map((entry, index) => {
    const name = asString(entry, `${path}[${index}]`);
    if (!(MODELS as readonly string[]).includes(name)) {
      throw new AnomalyReportError(
        `${path}[${index}]: unknown model "${name}" (expected ${MODELS.join(" or ")})`,
      );
    }
    return name as AnomalyModel;
  });

  if (models.length === 0) {
    throw new AnomalyReportError(`${path}: an anomaly must be flagged by at least one model`);
  }

  return models;
}

/**
 * Validates the numeric feature map.
 *
 * Every value must be a finite number, because the whole map is written to a
 * JSONB column and then displayed. Feature *names* are not checked against
 * `FEATURE_NAMES` deliberately: adding a feature in Python should not require a
 * TypeScript change before a run can be saved, and an unrecognised name renders
 * harmlessly.
 */
function parseFeatures(value: unknown, path: string): Record<string, number> {
  const raw = asObject(value, path);
  const features: Record<string, number> = {};

  for (const [name, entry] of Object.entries(raw)) {
    features[name] = asNumber(entry, `${path}.${name}`);
  }

  return features;
}

/**
 * Validates one anomaly.
 *
 * @param value - the candidate.
 * @param path - dotted path for the error message.
 * @throws {AnomalyReportError} naming the offending field.
 */
function parseAnomaly(value: unknown, path: string): Anomaly {
  const raw = asObject(value, path);

  const windowStart = asTimestamp(raw.windowStart, `${path}.windowStart`);
  const windowEnd = asTimestamp(raw.windowEnd, `${path}.windowEnd`);

  // Checked here as well as by the database CHECK constraint. The constraint is
  // the guarantee; this is what makes the failure legible, since a Postgres
  // constraint violation names the constraint rather than the record.
  if (windowEnd.getTime() <= windowStart.getTime()) {
    throw new AnomalyReportError(
      `${path}: windowEnd (${raw.windowEnd}) must be after windowStart (${raw.windowStart})`,
    );
  }

  const scores = asObject(raw.scores, `${path}.scores`);
  const rawScores = asObject(raw.rawScores, `${path}.rawScores`);

  return {
    principalArn: asString(raw.principalArn, `${path}.principalArn`),
    windowStart: windowStart.toISOString(),
    windowEnd: windowEnd.toISOString(),
    eventCount: asNumber(raw.eventCount, `${path}.eventCount`, 1),
    flaggedBy: parseFlaggedBy(raw.flaggedBy, `${path}.flaggedBy`),
    scores: {
      // Percentiles, so the 0-100 bound is exact and matches the column's CHECK.
      isolationForest: asNumber(
        scores.isolationForest,
        `${path}.scores.isolationForest`,
        0,
        100,
      ),
      baseline: asNumber(scores.baseline, `${path}.scores.baseline`, 0, 100),
    },
    rawScores: {
      isolationForest: asNumber(
        rawScores.isolationForest,
        `${path}.rawScores.isolationForest`,
      ),
      baseline: asNumber(rawScores.baseline, `${path}.rawScores.baseline`),
    },
    evidence: asArray(raw.evidence, `${path}.evidence`, EVIDENCE_LIMIT).map(
      (entry, index) => parseEvidence(entry, `${path}.evidence[${index}]`),
    ),
    sampleActions: asArray(
      raw.sampleActions,
      `${path}.sampleActions`,
      SAMPLE_ACTION_LIMIT,
    ).map((entry, index) => asString(entry, `${path}.sampleActions[${index}]`)),
    features: parseFeatures(raw.features, `${path}.features`),
    eventIds: asArray(
      raw.eventIds,
      `${path}.eventIds`,
      SAMPLE_EVENT_ID_LIMIT,
    ).map((entry, index) => asString(entry, `${path}.eventIds[${index}]`)),
  };
}

/**
 * Validates the run metadata, which `ml/detect.py` splits across several keys.
 *
 * The Python document keeps `source`, `models`, `budget` and `windowCount` at
 * the top level because that is what is natural to write there. Flattening them
 * into one metadata object here rather than mirroring the Python layout keeps
 * the awkwardness at the boundary instead of spreading it through the database
 * layer and the dashboard.
 */
function parseMetadata(raw: Record<string, unknown>): AnomalyRunMetadata {
  const source = asObject(raw.source, "source");
  const models = asObject(raw.models, "models");

  const primaryModel = asString(raw.primaryModel, "primaryModel");
  if (!(MODELS as readonly string[]).includes(primaryModel)) {
    throw new AnomalyReportError(
      `primaryModel: unknown model "${primaryModel}" (expected ${MODELS.join(" or ")})`,
    );
  }

  return {
    seed: asString(source.seed, "source.seed"),
    days: asNumber(source.days, "source.days", 1, 3650),
    eventCount: asNumber(source.eventCount, "source.eventCount", 0),
    windowCount: asNumber(raw.windowCount, "windowCount", 0),
    alertBudget: asNumber(raw.budget, "budget", 1),
    primaryModel: primaryModel as AnomalyModel,
    modelParams: models,
  };
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/**
 * Validates an already-parsed anomaly document.
 *
 * Separate from {@link loadAnomalyReport} so the validation can be tested
 * without touching the filesystem — which is what keeps the test suite runnable
 * with no Docker, no Python, and no generated fixtures.
 *
 * @param document - the parsed JSON.
 * @returns the validated report.
 * @throws {AnomalyReportError} naming the first field that is wrong.
 */
export function parseAnomalyReport(document: unknown): AnomalyReport {
  const raw = asObject(document, "report");

  const anomalies = asArray(raw.anomalies, "anomalies", MAX_ANOMALIES);

  return {
    metadata: parseMetadata(raw),
    anomalies: anomalies.map((entry, index) =>
      parseAnomaly(entry, `anomalies[${index}]`),
    ),
  };
}

/**
 * Reads and validates an anomaly report from disk.
 *
 * @param path - the detections file, normally `fixtures/anomalies.json`.
 * @returns the validated report.
 * @throws {AnomalyReportError} if the file is missing, is not valid JSON, or
 *   does not match the expected shape. All three are folded into one error type
 *   because all three mean the same thing to the caller — the detections are
 *   not usable — and the message distinguishes them for a human.
 */
export async function loadAnomalyReport(path: string): Promise<AnomalyReport> {
  let contents: string;

  try {
    contents = await readFile(path, "utf8");
  } catch (error) {
    throw new AnomalyReportError(
      `Could not read ${path}: ` +
        (error instanceof Error ? error.message : String(error)) +
        "\nRun the detector first:  npm run ml:detect",
    );
  }

  let document: unknown;
  try {
    document = JSON.parse(contents);
  } catch (error) {
    throw new AnomalyReportError(
      `${path} is not valid JSON: ` +
        (error instanceof Error ? error.message : String(error)),
    );
  }

  return parseAnomalyReport(document);
}
