-- CloudSentinel — behavioural anomaly schema: detection runs and their alerts.
--
-- Applied by `npm run db:migrate` (lib/db/migrate.ts) after 0002_dashboard.sql.
-- Like every migration in this directory it is append-only: once applied
-- anywhere, it is never edited. The runner stores a SHA-256 checksum of each
-- file it has run and refuses to continue if one changes.
--
-- Where this fits in the architecture:
--
--   0001: what the scanner observed about CONFIGURATION  (scans, findings)
--   0002: who is looking, and what they decided          (users, triage)
--   this: what the models observed about BEHAVIOUR       (anomaly_runs, anomalies)
--
--   lib/logs/generator.ts --> ml/detect.py --> fixtures/anomalies.json
--                                                       |
--                                              lib/anomalies/ingest.ts
--                                                       |
--                                                  [ this file ]
--                                                       |
--                                                   dashboard
--
-- ===========================================================================
-- The design decision that matters: anomalies have no lifecycle
-- ===========================================================================
--
-- The `findings` table in 0001 is carefully built around a lifecycle. A finding
-- is one distinct *problem* keyed by a deterministic id, and it carries
-- `first_seen_at`, `last_seen_at` and a `status` of open or resolved, because a
-- public S3 bucket is a condition that persists until somebody fixes it. That
-- design is what lets the dashboard answer "this bucket has been public since
-- the 4th of August".
--
-- Anomalies are deliberately NOT modelled that way, and the reason is worth
-- stating plainly because copying the findings design here would look
-- consistent and be wrong.
--
-- An anomaly is an observation about a *specific past hour*. Alice's 03:00
-- window on the 16th of June either looked strange or it did not, and nothing
-- anyone does afterwards changes that. There is no "fixing" 3am. A `status` of
-- open/resolved would be meaningless, and a `last_seen_at` would be a
-- contradiction — the window is over.
--
-- So an anomaly row is immutable once written: it belongs to the run that
-- produced it, records what that run saw, and is never updated. Re-running
-- detection produces a new run rather than mutating the old one, which also
-- means two runs at different sensitivities can be compared side by side
-- instead of one silently overwriting the other.
--
-- What an anomaly *can* acquire is a human verdict — "we looked, it was the
-- quarterly export" — and that is the same shape as `finding_triage` in 0002.
-- It is deliberately not built here; see the follow-ups in CLAUDE.md.
--
-- ===========================================================================
-- Why the run is a first-class table
-- ===========================================================================
--
-- Detection output depends on parameters: which log, which seed, how many
-- windows, and above all what alert budget. The same activity scored at a 0.5%
-- budget and a 2% budget produces different alerts, and an anomalies table with
-- no record of which settings produced a row would be uninterpretable within a
-- week. `anomaly_runs` pins that context so every alert can be traced back to
-- the exact configuration and input that produced it.

-- ---------------------------------------------------------------------------
-- anomaly_runs
-- ---------------------------------------------------------------------------

-- One execution of the detection pipeline.
CREATE TABLE anomaly_runs (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    -- When the detection was ingested. Distinct from the period the log covers,
    -- which is described by the columns below — analysing a month-old log today
    -- is a normal thing to do and the two dates must not be conflated.
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Provenance of the analysed log. Together these reproduce the exact input:
    -- `npm run logs:gen -- --seed <log_seed> --days <log_days>` regenerates it
    -- byte for byte, because generation is deterministic (lib/util/random.ts).
    --
    -- This is the whole reason the generated log is not committed: it does not
    -- need to be, as long as every consumer records how to rebuild it.
    log_seed        TEXT NOT NULL,
    log_days        INTEGER NOT NULL CHECK (log_days > 0),
    event_count     INTEGER NOT NULL CHECK (event_count >= 0),

    -- How many principal-hour windows were scored, and how many alerts each
    -- model was allowed to raise.
    --
    -- `alert_budget` is the single most important number for interpreting a
    -- run. It is an operational capacity choice — how many hours a month
    -- somebody will investigate — not an estimate of how much intrusion is in
    -- the data. Reading a precision figure without it is meaningless, since a
    -- larger budget mechanically lowers precision.
    window_count    INTEGER NOT NULL CHECK (window_count >= 0),
    alert_budget    INTEGER NOT NULL CHECK (alert_budget > 0),

    -- Which model the dashboard should present by default. Both are stored on
    -- every anomaly, so this is a display preference rather than a filter.
    primary_model   TEXT NOT NULL
                    CHECK (primary_model IN ('isolation_forest', 'baseline')),

    -- Model hyperparameters, as reported by ml/detect.py.
    --
    -- JSONB rather than columns because these differ per model and will change
    -- as models are tuned or added. Promoting each one to a column would mean a
    -- migration every time a parameter is introduced, and most of them are only
    -- ever read by a human trying to reproduce a run.
    model_params    JSONB NOT NULL
);

CREATE INDEX anomaly_runs_detected_at_idx ON anomaly_runs (detected_at DESC);

-- ---------------------------------------------------------------------------
-- anomalies
-- ---------------------------------------------------------------------------

-- One flagged principal-hour window.
CREATE TABLE anomalies (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    -- Cascade on delete: an anomaly is meaningless without the run that gives
    -- it context, so removing a run must not leave orphans behind claiming to
    -- be alerts from nowhere.
    run_id            BIGINT NOT NULL
                      REFERENCES anomaly_runs (id) ON DELETE CASCADE,

    -- Who, and when. The ARN is the analysis key throughout the ML layer —
    -- every feature is computed per principal, because "unusual" only means
    -- anything relative to a principal's own history.
    principal_arn     TEXT NOT NULL,
    window_start      TIMESTAMPTZ NOT NULL,
    window_end        TIMESTAMPTZ NOT NULL,

    event_count       INTEGER NOT NULL CHECK (event_count > 0),

    -- Which models flagged this window.
    --
    -- Stored as an array rather than a boolean per model so that adding a third
    -- detector needs no schema change. A window flagged by both models is a
    -- stronger signal than one flagged by either alone, and the dashboard says
    -- so — which is only possible because the union is recorded rather than
    -- just the primary model's opinion.
    flagged_by        TEXT[] NOT NULL CHECK (cardinality(flagged_by) > 0),

    -- Rank percentiles, 0-100, higher meaning more anomalous.
    --
    -- Percentiles rather than the models' raw scores because a robust z-score
    -- of 75 and a forest score of 0.19 are not comparable numbers, and putting
    -- either raw value in front of a reader would mean nothing to them. The raw
    -- values are kept in `features`/`model_params` for anyone reproducing a run.
    --
    -- Both are NOT NULL: every window is scored by both models even when only
    -- one flagged it, and that is exactly what makes disagreement visible.
    score_isolation_forest  NUMERIC(5, 2) NOT NULL
                            CHECK (score_isolation_forest BETWEEN 0 AND 100),
    score_baseline          NUMERIC(5, 2) NOT NULL
                            CHECK (score_baseline BETWEEN 0 AND 100),

    -- Why this window looks strange, in plain language.
    --
    -- An array of {feature, zScore, description}. This exists because an
    -- Isolation Forest cannot explain itself: its output is an average path
    -- length, and there is no meaningful way to attribute that to one column.
    -- An alert reading "score 99.9" gives an analyst nowhere to start, and after
    -- a few of those they stop reading alerts entirely.
    --
    -- The contents come from the statistical model's per-feature scores — the
    -- forest decides WHAT to flag, the baseline explains WHY it is unusual.
    -- That is strong evidence but not the forest's internal reasoning, and the
    -- dashboard says so rather than overclaiming.
    --
    -- May be an empty array, which is meaningful rather than a failure: a window
    -- isolated on a *combination* of individually unremarkable features
    -- genuinely has no single feature worth pointing at, and inventing one would
    -- be worse than admitting it.
    evidence          JSONB NOT NULL,

    -- The full feature vector, for the detail view and for reproducing a score.
    features          JSONB NOT NULL,

    -- The most common API actions in the window, for display.
    sample_actions    TEXT[] NOT NULL,

    -- A capped sample of the event ids in this window.
    --
    -- Capped deliberately by lib/anomalies/ingest.ts. The exfiltration window
    -- contains over three hundred events, and storing every id would bloat the
    -- row while giving an analyst nothing — nobody reads three hundred UUIDs.
    -- A sample is enough to pivot into the raw log, which is where the full list
    -- lives anyway.
    sample_event_ids  TEXT[] NOT NULL,

    -- A window cannot end before it starts.
    CONSTRAINT anomalies_window_order CHECK (window_end > window_start),

    -- One row per principal per window, within a run. This enforces the
    -- invariant that a run holds a single verdict for any given principal-hour;
    -- a detections file that listed the same window twice is malformed, and the
    -- database says so rather than storing two contradictory alerts.
    --
    -- Note what it deliberately does NOT do: it does not deduplicate across
    -- runs. Saving the same detections file twice produces two runs, exactly as
    -- re-scanning produces a new `scans` row rather than overwriting the last
    -- one. A run records an analysis that happened, and saving the same log at
    -- two different alert budgets to compare them is a thing worth being able
    -- to do.
    CONSTRAINT anomalies_unique_window UNIQUE (run_id, principal_arn, window_start)
);

CREATE INDEX anomalies_run_id_idx ON anomalies (run_id);
CREATE INDEX anomalies_principal_idx ON anomalies (principal_arn);
CREATE INDEX anomalies_window_start_idx ON anomalies (window_start DESC);

-- Ordering the anomaly list by severity within a run is the dashboard's most
-- common query, so it gets a matching composite index.
CREATE INDEX anomalies_run_score_idx
    ON anomalies (run_id, score_isolation_forest DESC);
