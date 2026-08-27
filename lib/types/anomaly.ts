/**
 * CloudSentinel — behavioural anomaly model.
 *
 * The TypeScript view of what the Python ML layer produces. Types only: no
 * imports, no logic, nothing that runs at runtime.
 *
 * Where it sits in the architecture: the second half of the cross-language
 * boundary. `lib/types/cloudtrail.ts` describes what TypeScript sends *to*
 * Python; this file describes what comes back.
 *
 *   ml/detect.py --> fixtures/anomalies.json --> lib/anomalies/ingest.ts
 *                            |                            |
 *                     (this file's shape)                 v
 *                                                   Postgres --> dashboard
 *
 * Because `ml/detect.py` writes these field names by hand, this file is a
 * contract in exactly the way `lib/types/cloudtrail.ts` is, and the same
 * warning applies: Python cannot type-check against TypeScript, so a rename on
 * either side is caught at runtime rather than at build time. The difference is
 * that here the mismatch is caught immediately and clearly, because
 * `lib/anomalies/ingest.ts` validates every field before anything reaches the
 * database — see that file for why validation is worth the effort at this one
 * boundary when the inventory loader in `scripts/scan.ts` deliberately skips it.
 *
 * Note that these are `camelCase` where the CloudTrail types are not. That is
 * not an inconsistency: `lib/types/cloudtrail.ts` mirrors AWS's own wire format
 * and keeps AWS's spelling so a real trail would need no translation, whereas
 * this document is CloudSentinel's own invention and follows CloudSentinel's
 * conventions.
 */

// ---------------------------------------------------------------------------
// Models
// ---------------------------------------------------------------------------

/**
 * Which detector flagged a window.
 *
 *   - `isolation_forest` — the scikit-learn model (`ml/detect.py`).
 *   - `baseline` — the dependency-free statistical control (`ml/baseline.py`).
 *
 * Both are always run and both always score every window. Keeping the two
 * separate all the way through to the dashboard is the point: it is what allows
 * the interface to show *disagreement*, and disagreement is informative. A
 * window both models flagged is a stronger signal than one only the forest
 * isolated, and a reader can see which is which instead of being handed a
 * single unexplained verdict.
 */
export type AnomalyModel = "isolation_forest" | "baseline";

/**
 * One reason a window looked unusual.
 *
 * Produced from the statistical model's per-feature robust z-scores, even for
 * detections the Isolation Forest made. The forest has no per-feature
 * explanation to give — its score is an average path length across random
 * trees, which cannot be attributed to a single column — so the evidence shown
 * to an analyst comes from the model that *can* explain itself.
 *
 * That pairing is stated honestly here and in the UI: these are the features
 * that made the window statistically extreme, which is strong supporting
 * evidence, not a reconstruction of the forest's internal reasoning.
 */
export interface AnomalyEvidence {
  /** The feature name, e.g. `"volume_ratio"`. Matches `ml/features.py`. */
  feature: string;

  /**
   * How many robust standard deviations from this principal's median.
   *
   * Capped at 25 by `ml/baseline.py`. Several features are near-constant for a
   * given principal, and an uncapped score reached the hundreds — a number that
   * says nothing except that the feature almost never moves, and that would
   * destroy a reader's trust in the evidence section.
   */
  zScore: number;

  /** Plain-language explanation, for a reader who does not know the feature. */
  description: string;
}

// ---------------------------------------------------------------------------
// Detections
// ---------------------------------------------------------------------------

/**
 * One flagged principal-hour window.
 *
 * Deliberately immutable and self-contained. Unlike a `Finding` (see
 * `lib/rules/types.ts`), an anomaly has no lifecycle and no stable identity
 * across runs: it is an observation about one specific past hour, and nothing
 * that happens later changes whether that hour looked strange. The reasoning is
 * written out at length in `db/migrations/0003_anomalies.sql`.
 */
export interface Anomaly {
  /** ARN of the principal whose behaviour was flagged. */
  principalArn: string;

  /** ISO 8601 UTC start of the one-hour window. */
  windowStart: string;

  /** ISO 8601 UTC end of the window. */
  windowEnd: string;

  /** How many API calls the principal made in the window. */
  eventCount: number;

  /** Which models flagged it. Never empty. */
  flaggedBy: AnomalyModel[];

  /**
   * Rank percentiles, 0-100, higher meaning more anomalous.
   *
   * Both models score every window, so both values are always present even when
   * only one model flagged it — which is precisely what makes a disagreement
   * legible rather than invisible.
   *
   * Percentiles rather than raw scores because the two models' native scales
   * are not comparable, and because a single extreme outlier would compress
   * every other alert to the bottom of a min-max range.
   */
  scores: {
    isolationForest: number;
    baseline: number;
  };

  /** The models' native scores, kept so a run can be reproduced or audited. */
  rawScores: {
    isolationForest: number;
    baseline: number;
  };

  /**
   * Why this window is unusual, worst first.
   *
   * May be empty. That is a real answer rather than a gap: a window isolated on
   * a *combination* of individually unremarkable features has no single feature
   * worth naming, and manufacturing one would mislead.
   */
  evidence: AnomalyEvidence[];

  /** The most common API actions in the window, for display. */
  sampleActions: string[];

  /** Every extracted feature and its value, for the detail view. */
  features: Record<string, number>;

  /**
   * Event ids from this window.
   *
   * Capped on ingest — see `SAMPLE_EVENT_ID_LIMIT` in `lib/anomalies/ingest.ts`.
   * The exfiltration window holds over three hundred, and nobody reads three
   * hundred UUIDs.
   */
  eventIds: string[];
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

/**
 * Provenance and configuration of one detection run.
 *
 * Detection output depends on its parameters — above all the alert budget — so
 * a set of anomalies without this context cannot be interpreted. Precision in
 * particular falls mechanically as the budget rises, and a figure quoted
 * without the budget beside it is not a figure at all.
 */
export interface AnomalyRunMetadata {
  /**
   * The seed of the analysed log.
   *
   * With `days`, this reproduces the exact input: generation is deterministic,
   * so `npm run logs:gen -- --seed <seed> --days <days>` rebuilds it byte for
   * byte. Recording this is what makes it safe not to commit the log.
   */
  seed: string;

  /** How many days of activity the log covered. */
  days: number;

  /** How many events were analysed. */
  eventCount: number;

  /** How many principal-hour windows were scored. */
  windowCount: number;

  /**
   * How many alerts each model was allowed to raise.
   *
   * An operational capacity decision — roughly "how many hours a month will
   * somebody investigate" — not an estimate of how much intrusion is present.
   * Both models are held to the same budget so the comparison between them
   * measures which spends attention better rather than which alerts more.
   */
  alertBudget: number;

  /** Which model the dashboard presents by default. */
  primaryModel: AnomalyModel;

  /** Model hyperparameters as reported by `ml/detect.py`. */
  modelParams: Record<string, unknown>;
}

/**
 * The complete document written by `ml/detect.py` and read on ingest.
 */
export interface AnomalyReport {
  metadata: AnomalyRunMetadata;

  /** The flagged windows, most anomalous first by the primary model. */
  anomalies: Anomaly[];
}
