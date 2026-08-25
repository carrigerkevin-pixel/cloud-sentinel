-- CloudSentinel — initial schema.
--
-- Applied by `npm run db:migrate` (lib/db/migrate.ts), which records each file
-- it has run in `schema_migrations` and never runs one twice. Migrations are
-- append-only: once this file has been applied anywhere, it is never edited —
-- a change goes in a new numbered file. Editing an applied migration means the
-- database someone already has and the SQL in the repository silently disagree,
-- which is the kind of drift nobody discovers until a deploy fails.
--
-- Where this fits in the architecture:
--
--   collectors --> rule engine --> ScanResult --> [ these tables ] --> dashboard
--
-- The central design problem this schema solves is *finding lifecycle*.
--
-- The rule engine is stateless: it recomputes every finding from scratch on
-- every run, and by itself can only ever answer "what is wrong right now". That
-- is a linter. What makes a posture-management tool useful is the other
-- question — "what is NEW, what is still open three weeks later, and what did
-- we actually fix?" Answering it requires remembering previous scans and
-- matching findings across them.
--
-- Matching is possible because finding ids are deterministic:
-- `<ruleId>|<resourceId>|<key>`, built in lib/rules/engine.ts from the
-- configuration rather than from array position. The same problem in the same
-- environment produces the same id on every scan, forever. That property is
-- what the whole `findings` table below rests on.
--
-- Hence the split between two tables that at first look redundant:
--
--   findings            one row per distinct problem, ever. Carries the
--                       lifecycle: first_seen_at, last_seen_at, status.
--   finding_occurrences one row per (scan, finding). The evidence a specific
--                       scan produced.
--
-- Keeping occurrences separately is what allows "this bucket has been public
-- since the 4th of August" to be answered at all, and it keeps the audit trail
-- honest: the row recording what scan #12 saw is never rewritten by scan #13.

-- ---------------------------------------------------------------------------
-- scans
-- ---------------------------------------------------------------------------

-- One row per completed scan.
--
-- Stores provenance (which environment, collected when) alongside the summary
-- counts, so the dashboard can render a scan history list without touching the
-- findings tables at all.
CREATE TABLE scans (
    -- Identity column rather than `serial`: it is the SQL-standard spelling,
    -- and it blocks an accidental explicit insert into the id, which `serial`
    -- permits and which desynchronises the underlying sequence.
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    -- When the environment was observed, and when the rules ran over it. These
    -- are deliberately separate: re-running the engine against a saved
    -- inventory produces a new scan whose findings still date from the original
    -- collection. Conflating them would make last week's problems look like
    -- today's.
    collected_at     TIMESTAMPTZ NOT NULL,
    scanned_at       TIMESTAMPTZ NOT NULL,

    -- Which environment this came from. Recorded because a findings history is
    -- meaningless if it cannot say what it was looking at — and because mixing
    -- two environments' scans in one table would silently corrupt every
    -- lifecycle calculation below.
    endpoint         TEXT NOT NULL,
    region           TEXT NOT NULL,

    resources_scanned INTEGER NOT NULL,
    resources_clean   INTEGER NOT NULL,
    risk_score        INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),

    -- Carried over from the inventory. A scan with collection errors did not
    -- see the whole environment, and the lifecycle logic in lib/db/lifecycle.ts
    -- refuses to resolve findings based on one. Storing the count means that
    -- decision can be audited later rather than being invisible.
    collection_errors INTEGER NOT NULL DEFAULT 0,

    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE scans IS
    'One completed run of the rule engine over one collected inventory.';

CREATE INDEX scans_collected_at_idx ON scans (collected_at DESC);

-- ---------------------------------------------------------------------------
-- resources
-- ---------------------------------------------------------------------------

-- The resources a given scan observed.
--
-- Scoped to a scan rather than being a global resource inventory, because the
-- interesting question is "what did this scan see" — and because it is what
-- lets the lifecycle logic distinguish "this bucket is no longer public" from
-- "this bucket no longer exists". Without a record of which resources were
-- present, a finding disappearing is ambiguous, and guessing wrong means either
-- claiming credit for a fix that never happened or leaving a resolved finding
-- open forever.
CREATE TABLE resources (
    scan_id      BIGINT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,

    -- The stable AWS identifier: an ARN, or `sg-...` where no ARN exists.
    resource_id  TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    name         TEXT NOT NULL,
    region       TEXT NOT NULL,

    -- Tags and the full service-specific config, kept as JSONB.
    --
    -- JSONB rather than one table per service: the three config shapes have
    -- almost nothing in common, so normalising them would mean three tables and
    -- a join to answer any cross-service question. This keeps the mixed
    -- inventory queryable in one place, which is exactly the trade lib/types/
    -- resource.ts anticipated when it separated the common envelope from
    -- `config`.
    tags         JSONB NOT NULL DEFAULT '{}'::jsonb,
    config       JSONB NOT NULL,

    -- Settings this scan could not read. The same three-state honesty the rule
    -- engine enforces, persisted: a stored scan must still be able to say it
    -- did not manage to look at something.
    unobserved   TEXT[] NOT NULL DEFAULT '{}',

    PRIMARY KEY (scan_id, resource_id)
);

COMMENT ON TABLE resources IS
    'Resources observed by one scan. Not a global inventory — scoped per scan.';

CREATE INDEX resources_resource_id_idx ON resources (resource_id);

-- ---------------------------------------------------------------------------
-- findings — the lifecycle record
-- ---------------------------------------------------------------------------

-- One row per distinct problem, for the lifetime of that problem.
--
-- The primary key is the engine's deterministic finding id, so re-scanning an
-- unchanged environment updates these rows in place rather than inserting
-- duplicates. That single decision is what turns a pile of scan output into a
-- lifecycle.
--
-- Rule metadata (title, severity, remediation) is denormalised into this table
-- rather than joined from a rules table. Rules live in TypeScript, not in the
-- database, and a finding needs to stay readable after the rule that produced
-- it has been retuned or removed — the historical record should say what was
-- reported at the time, not what the current rule set would say now.
CREATE TABLE findings (
    id             TEXT PRIMARY KEY,

    rule_id        TEXT NOT NULL,
    title          TEXT NOT NULL,
    severity       TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    benchmark      TEXT NOT NULL,
    remediation    TEXT NOT NULL,

    resource_id    TEXT NOT NULL,
    resource_name  TEXT NOT NULL,
    resource_type  TEXT NOT NULL,
    region         TEXT NOT NULL,

    -- Lifecycle. `open` means the most recent scan that could see this resource
    -- still reported the problem; `resolved` means it did not.
    status         TEXT NOT NULL CHECK (status IN ('open', 'resolved')),

    -- Why it was resolved, so "we fixed it" and "the resource was deleted" stay
    -- distinguishable. Deleting a public bucket does close the finding, but it
    -- is not the same event as making the bucket private, and a compliance
    -- report that cannot tell them apart is easy to game.
    resolution_reason TEXT CHECK (
        resolution_reason IN ('fixed', 'resource_removed')
    ),

    -- The dates that make the table worth having.
    first_seen_at  TIMESTAMPTZ NOT NULL,
    last_seen_at   TIMESTAMPTZ NOT NULL,
    resolved_at    TIMESTAMPTZ,

    first_seen_scan_id BIGINT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    last_seen_scan_id  BIGINT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,

    -- Enforce the two states in the database rather than trusting application
    -- code. A resolved finding must say when and why; an open one must claim
    -- neither. Left to convention, this is exactly the invariant that drifts
    -- once a second code path starts writing to the table.
    CONSTRAINT findings_resolution_consistent CHECK (
        (status = 'open'     AND resolved_at IS NULL     AND resolution_reason IS NULL) OR
        (status = 'resolved' AND resolved_at IS NOT NULL AND resolution_reason IS NOT NULL)
    )
);

COMMENT ON TABLE findings IS
    'One row per distinct problem, carrying its lifecycle across scans.';

CREATE INDEX findings_status_severity_idx ON findings (status, severity);
CREATE INDEX findings_resource_id_idx ON findings (resource_id);
CREATE INDEX findings_rule_id_idx ON findings (rule_id);
CREATE INDEX findings_first_seen_at_idx ON findings (first_seen_at DESC);

-- ---------------------------------------------------------------------------
-- finding_occurrences — the per-scan audit trail
-- ---------------------------------------------------------------------------

-- What one specific scan reported about one specific finding.
--
-- Append-only in practice: a row here records what was true at the time and is
-- never rewritten by a later scan. That is what separates an audit trail from a
-- status field.
--
-- It also carries `status`, which is where `inconclusive` lives. The lifecycle
-- table above has only `open` and `resolved`, because "we could not check"
-- is a property of a *scan*, not of a problem — the bucket either is public or
-- is not, regardless of whether one particular run managed to look.
CREATE TABLE finding_occurrences (
    scan_id     BIGINT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    finding_id  TEXT NOT NULL REFERENCES findings (id) ON DELETE CASCADE,

    -- 'fail' or 'inconclusive' — the two non-passing rule verdicts.
    status      TEXT NOT NULL CHECK (status IN ('fail', 'inconclusive')),

    -- Severity is stored per occurrence as well as on the finding, because a
    -- rule may assign a different severity to the same finding as conditions
    -- change (a partially-disabled control is `high` where a fully-disabled one
    -- is `critical`). The history should show that movement.
    severity    TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),

    -- The evidence this scan produced: real observed values, quoted.
    detail      TEXT NOT NULL,

    -- When the environment was observed, denormalised from `scans` so that
    -- charting a finding's history needs no join.
    detected_at TIMESTAMPTZ NOT NULL,

    PRIMARY KEY (scan_id, finding_id)
);

COMMENT ON TABLE finding_occurrences IS
    'What a specific scan reported about a specific finding. Append-only.';

CREATE INDEX finding_occurrences_finding_id_idx
    ON finding_occurrences (finding_id, detected_at DESC);
