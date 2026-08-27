/**
 * CloudSentinel — tests for anomaly report validation.
 *
 * Run with `npm test`. Pure logic: no filesystem, no database, no Python.
 *
 * These tests exercise the guard on the return leg of the cross-language
 * boundary. The thing being protected against is not a malicious file — it is
 * the far more likely case of `ml/detect.py` being changed and the two sides
 * drifting apart silently. TypeScript cannot check Python, so this validator is
 * the only place that mismatch can be caught, and a validator with no tests is
 * a validator nobody should rely on.
 *
 * Almost every test below is a *rejection* test. That is deliberate: a
 * validator that accepts good input is easy and is proved by the pipeline
 * working at all. What needs proving is that it refuses bad input rather than
 * quietly passing `undefined` or `NaN` through to a database column, where it
 * surfaces much later as a constraint violation a user experiences as a 500.
 */

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  AnomalyReportError,
  parseAnomalyReport,
  SAMPLE_EVENT_ID_LIMIT,
} from "./ingest.ts";

/**
 * A minimal well-formed anomaly, in the shape `ml/detect.py` writes.
 *
 * Built fresh by a function rather than shared as a constant so a test that
 * mutates it cannot affect another — the classic shared-fixture bug, which in a
 * validation suite would produce confidently wrong results.
 */
function validAnomaly(): Record<string, unknown> {
  return {
    principalArn: "arn:aws:iam::123456789012:user/alice-analyst",
    windowStart: "2026-06-16T03:00:00Z",
    windowEnd: "2026-06-16T04:00:00Z",
    eventCount: 9,
    flaggedBy: ["isolation_forest", "baseline"],
    scores: { isolationForest: 99.9, baseline: 75.0 },
    rawScores: { isolationForest: 0.187, baseline: 75.0 },
    evidence: [
      {
        feature: "sensitive_novelty",
        zScore: 25,
        description: "sensitive calls weighed against history",
      },
    ],
    sampleActions: ["AttachUserPolicy", "CreateAccessKey"],
    features: { sensitive_novelty: 4, event_count: 9 },
    eventIds: ["11111111-1111-4111-8111-111111111111"],
  };
}

/** A minimal well-formed report. */
function validReport(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    source: { seed: "cloudsentinel", days: 30, eventCount: 36461 },
    models: { isolationForest: { nEstimators: 200 }, baseline: {} },
    primaryModel: "isolation_forest",
    budget: 20,
    windowCount: 1990,
    anomalies: [validAnomaly()],
    ...overrides,
  };
}

/** Builds a report whose single anomaly has one field replaced. */
function reportWithAnomalyField(
  field: string,
  value: unknown,
): Record<string, unknown> {
  const anomaly = validAnomaly();
  if (value === undefined) {
    delete anomaly[field];
  } else {
    anomaly[field] = value;
  }
  return validReport({ anomalies: [anomaly] });
}

// ---------------------------------------------------------------------------
// Acceptance
// ---------------------------------------------------------------------------

describe("parseAnomalyReport — valid input", () => {
  test("parses a well-formed report", () => {
    const report = parseAnomalyReport(validReport());

    assert.equal(report.anomalies.length, 1);
    assert.equal(report.metadata.seed, "cloudsentinel");
    assert.equal(report.metadata.alertBudget, 20);
    assert.equal(report.metadata.primaryModel, "isolation_forest");
  });

  test("flattens the Python document's scattered metadata keys", () => {
    // ml/detect.py writes `source`, `models`, `budget` and `windowCount` at the
    // top level. Normalising them into one metadata object here keeps the
    // awkwardness at the boundary rather than spreading it into the database
    // layer and the dashboard.
    const report = parseAnomalyReport(validReport());

    assert.equal(report.metadata.days, 30);
    assert.equal(report.metadata.eventCount, 36461);
    assert.equal(report.metadata.windowCount, 1990);
    assert.deepEqual(report.metadata.modelParams, {
      isolationForest: { nEstimators: 200 },
      baseline: {},
    });
  });

  test("accepts an empty evidence list", () => {
    // Meaningful rather than missing: a window the forest isolated on a
    // combination of unremarkable features genuinely has no single feature
    // worth naming, and rejecting that would force the Python side to invent one.
    const report = parseAnomalyReport(reportWithAnomalyField("evidence", []));

    assert.deepEqual(report.anomalies[0]!.evidence, []);
  });

  test("accepts a report with no anomalies", () => {
    // A clean run is a legitimate result, not an error — it is what
    // `npm run logs:gen -- --no-attacks` is for.
    const report = parseAnomalyReport(validReport({ anomalies: [] }));

    assert.deepEqual(report.anomalies, []);
  });

  test("normalises timestamps to ISO form", () => {
    const report = parseAnomalyReport(
      reportWithAnomalyField("windowStart", "2026-06-16T03:00:00.000Z"),
    );

    assert.equal(report.anomalies[0]!.windowStart, "2026-06-16T03:00:00.000Z");
  });
});

// ---------------------------------------------------------------------------
// Structural rejection
// ---------------------------------------------------------------------------

describe("parseAnomalyReport — structural rejection", () => {
  test("rejects a non-object document", () => {
    assert.throws(() => parseAnomalyReport(null), AnomalyReportError);
    assert.throws(() => parseAnomalyReport("a string"), AnomalyReportError);
    assert.throws(() => parseAnomalyReport([]), AnomalyReportError);
  });

  test("rejects a missing anomalies array", () => {
    const report = validReport();
    delete report.anomalies;

    assert.throws(() => parseAnomalyReport(report), AnomalyReportError);
  });

  test("rejects missing metadata", () => {
    const report = validReport();
    delete report.source;

    assert.throws(() => parseAnomalyReport(report), AnomalyReportError);
  });

  test("names the offending field in the error message", () => {
    // The whole point of validating here rather than letting Postgres complain
    // is that the message says which field, in which record. A generic "invalid
    // input" would be no better than the constraint violation it replaces.
    assert.throws(
      () => parseAnomalyReport(reportWithAnomalyField("eventCount", "nine")),
      /anomalies\[0\]\.eventCount/,
    );
  });
});

// ---------------------------------------------------------------------------
// Numeric rejection
// ---------------------------------------------------------------------------

describe("parseAnomalyReport — numeric validation", () => {
  test("rejects a non-numeric score", () => {
    const anomaly = validAnomaly();
    anomaly.scores = { isolationForest: "high", baseline: 75 };

    assert.throws(
      () => parseAnomalyReport(validReport({ anomalies: [anomaly] })),
      /scores\.isolationForest/,
    );
  });

  test("rejects a percentile outside 0-100", () => {
    // The database column is NUMERIC(5,2) with a CHECK constraint. Catching it
    // here turns a 500 into a clear ingestion error naming the record.
    for (const bad of [-1, 100.01, 1000]) {
      const anomaly = validAnomaly();
      anomaly.scores = { isolationForest: bad, baseline: 50 };

      assert.throws(
        () => parseAnomalyReport(validReport({ anomalies: [anomaly] })),
        AnomalyReportError,
        `expected ${bad} to be rejected`,
      );
    }
  });

  test("rejects null where a number is required", () => {
    // JSON has no NaN literal, but it does have null — and `Number(null)` is 0,
    // so an unchecked cast would silently store a score of zero for a window
    // the model actually ranked highest.
    const anomaly = validAnomaly();
    anomaly.scores = { isolationForest: null, baseline: 50 };

    assert.throws(
      () => parseAnomalyReport(validReport({ anomalies: [anomaly] })),
      AnomalyReportError,
    );
  });

  test("rejects a zero or negative event count", () => {
    // A window with no events cannot have been flagged; the count is wrong.
    for (const bad of [0, -5]) {
      assert.throws(
        () => parseAnomalyReport(reportWithAnomalyField("eventCount", bad)),
        AnomalyReportError,
        `expected ${bad} to be rejected`,
      );
    }
  });

  test("rejects a non-numeric feature value", () => {
    assert.throws(
      () =>
        parseAnomalyReport(
          reportWithAnomalyField("features", { volume_ratio: "large" }),
        ),
      /features\.volume_ratio/,
    );
  });
});

// ---------------------------------------------------------------------------
// Domain rejection
// ---------------------------------------------------------------------------

describe("parseAnomalyReport — domain validation", () => {
  test("rejects an unknown model name", () => {
    // Means the Python side grew a detector the dashboard cannot render. Better
    // to refuse the run than to display a blank badge nobody can interpret.
    assert.throws(
      () => parseAnomalyReport(reportWithAnomalyField("flaggedBy", ["deep_learning"])),
      /unknown model/,
    );
  });

  test("rejects an anomaly flagged by nothing", () => {
    assert.throws(
      () => parseAnomalyReport(reportWithAnomalyField("flaggedBy", [])),
      AnomalyReportError,
    );
  });

  test("rejects an unknown primary model", () => {
    assert.throws(
      () => parseAnomalyReport(validReport({ primaryModel: "magic" })),
      /unknown model/,
    );
  });

  test("rejects an invalid timestamp", () => {
    assert.throws(
      () => parseAnomalyReport(reportWithAnomalyField("windowStart", "yesterday")),
      /not a valid timestamp/,
    );
  });

  test("rejects a window that ends before it starts", () => {
    // Also enforced by a CHECK constraint. Both exist on purpose: the
    // constraint is the guarantee, this is what makes the failure readable.
    assert.throws(
      () =>
        parseAnomalyReport(
          reportWithAnomalyField("windowEnd", "2026-06-16T02:00:00Z"),
        ),
      /must be after windowStart/,
    );
  });

  test("rejects an empty principal ARN", () => {
    assert.throws(
      () => parseAnomalyReport(reportWithAnomalyField("principalArn", "")),
      AnomalyReportError,
    );
  });
});

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

describe("parseAnomalyReport — bounds", () => {
  test("caps the number of stored event ids", () => {
    // The exfiltration window holds over three hundred. Storing every id would
    // bloat the row and give an analyst nothing — nobody reads 300 UUIDs.
    const ids = Array.from(
      { length: 500 },
      (_, index) => `id-${String(index).padStart(4, "0")}`,
    );

    const report = parseAnomalyReport(reportWithAnomalyField("eventIds", ids));

    assert.equal(report.anomalies[0]!.eventIds.length, SAMPLE_EVENT_ID_LIMIT);
    // The cap keeps the *first* ids, so the sample is the start of the window
    // rather than an arbitrary slice.
    assert.equal(report.anomalies[0]!.eventIds[0], "id-0000");
  });

  test("rejects an absurdly long string", () => {
    assert.throws(
      () =>
        parseAnomalyReport(
          reportWithAnomalyField("principalArn", "a".repeat(5000)),
        ),
      /exceeds the/,
    );
  });

  test("rejects a non-array where an array is required", () => {
    assert.throws(
      () => parseAnomalyReport(reportWithAnomalyField("sampleActions", "GetObject")),
      /expected an array/,
    );
  });
});
