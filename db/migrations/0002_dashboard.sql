-- CloudSentinel — dashboard schema: users, authentication, and finding triage.
--
-- Applied by `npm run db:migrate` (lib/db/migrate.ts) after 0001_init.sql.
-- Like every migration in this directory it is append-only: once applied
-- anywhere, it is never edited. The runner stores a SHA-256 checksum of each
-- file it has run and refuses to continue if one changes, because a database
-- that silently disagrees with the SQL in the repository is a problem nobody
-- discovers until a deploy fails.
--
-- Where this fits in the architecture:
--
--   collectors --> rule engine --> [ 0001: scans, findings ] --> dashboard
--                                                                   ^
--                                              [ this file: who is looking,
--                                                and what they decided ]
--
-- 0001 stores what the *machine* observed. This migration stores what a
-- *person* concluded about it, and who that person is. Those are deliberately
-- two different things, which is the single most important idea in this file —
-- see the note above `finding_triage` below.

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------

-- Dashboard accounts.
--
-- CloudSentinel reports on which IAM users have weak authentication, so its own
-- authentication has to survive the same questions it asks of other people's.
-- The choices here are made with that in mind.
CREATE TABLE users (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    -- Stored already lowercased and trimmed by the application layer, with a
    -- UNIQUE index doing the enforcing and a CHECK making the invariant true in
    -- the database rather than by convention. Case-folding at write time rather
    -- than comparing case-insensitively at read time means there is exactly one
    -- spelling of an account in the table — otherwise `Kevin@x.com` and
    -- `kevin@x.com` are two accounts, and revoking one leaves the other live.
    email          TEXT NOT NULL UNIQUE CHECK (email = lower(email)),

    -- SECURITY: a scrypt hash with its parameters and per-user salt encoded
    -- into the string, never a plaintext or reversibly-encrypted password. The
    -- format is `scrypt$N$r$p$<salt-b64>$<hash-b64>` — see lib/auth/password.ts.
    --
    -- Storing the cost parameters alongside the hash is what allows them to be
    -- raised later without invalidating existing passwords: an old hash still
    -- carries the parameters it was created with, so it can still be verified
    -- and then transparently re-hashed at the new cost on the next login.
    password_hash  TEXT NOT NULL,

    -- Two roles only. `admin` may change triage state; `viewer` is read-only.
    -- A finer-grained scheme would be easy to add and impossible to justify at
    -- this size — inventing permissions nobody uses is how authorization
    -- systems become the thing everyone routes around.
    role           TEXT NOT NULL DEFAULT 'viewer'
                   CHECK (role IN ('admin', 'viewer')),

    -- SECURITY: the JWT revocation mechanism.
    --
    -- A JWT is self-contained: once signed and handed out, the server keeps no
    -- record of it and has no way to take it back before it expires. That is
    -- the well-known cost of stateless auth. This column buys the revocation
    -- back for one extra integer of storage: the version is embedded as a claim
    -- in every token issued, and verification rejects any token whose claim
    -- does not match the current value here. Bumping it invalidates every token
    -- that user is holding, everywhere, immediately — which is what "log out
    -- all devices" and "this account may be compromised" both need.
    token_version  INTEGER NOT NULL DEFAULT 1,

    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Recorded on each successful login. Useful on its own, and it is the
    -- signal a future "dormant admin account" check would run on — the same
    -- class of finding CloudSentinel already reports about IAM users.
    last_login_at  TIMESTAMPTZ
);

COMMENT ON TABLE users IS
    'Dashboard accounts. Passwords are scrypt hashes; token_version revokes JWTs.';

-- ---------------------------------------------------------------------------
-- finding_triage — the human overlay
-- ---------------------------------------------------------------------------

-- What a person decided about a finding.
--
-- THE IMPORTANT PART: triage never touches `findings.status`.
--
-- `findings.status` (open / resolved) is the scanner's claim about reality, set
-- only by the lifecycle logic in lib/db/lifecycle.ts from what a scan actually
-- observed. `finding_triage.state` is a human's claim about what should be done
-- about it. Keeping them in separate columns in separate tables is a deliberate
-- refusal to let one overwrite the other.
--
-- The alternative — letting "suppress" flip a finding to resolved — would mean
-- the tool reports a bucket as fixed because somebody clicked a button, which
-- makes every compliance report it produces worthless. A finding can be
-- suppressed *and* still open, and the dashboard shows both facts. If the
-- bucket is still public, CloudSentinel still says so; suppression only moves
-- it out of the default view.
--
-- One row per finding, holding only the current state. The history of how it
-- got there lives in `triage_events` below.
CREATE TABLE finding_triage (
    finding_id  TEXT PRIMARY KEY REFERENCES findings (id) ON DELETE CASCADE,

    --   untriaged      nobody has looked at it yet
    --   acknowledged   real, seen, queued to fix
    --   suppressed     real, but accepted as a risk or not worth fixing
    --   false_positive the rule is wrong about this resource
    --
    -- `suppressed` and `false_positive` are kept apart on purpose. Both hide a
    -- finding, but one is a statement about the business and the other is a bug
    -- report about the rule set, and collapsing them loses the only feedback
    -- signal that says which rules are miscalibrated.
    state       TEXT NOT NULL
                CHECK (state IN ('untriaged', 'acknowledged', 'suppressed', 'false_positive')),

    note        TEXT,

    -- SECURITY: hiding a finding requires writing down why.
    --
    -- The single easiest way to defeat a posture-management tool is to make the
    -- inconvenient findings quietly disappear. Requiring a non-empty
    -- justification for every non-default state does not prevent that, but it
    -- does mean the decision is attributable and reviewable rather than
    -- invisible.
    CONSTRAINT finding_triage_note_required CHECK (
        state = 'untriaged' OR (note IS NOT NULL AND length(btrim(note)) > 0)
    ),

    -- Nullable, and ON DELETE SET NULL: deleting a user account must not
    -- cascade-delete the findings they triaged. The durable record of who did
    -- it lives in `triage_events.actor_email`, which is plain text and survives
    -- the account being removed.
    updated_by  BIGINT REFERENCES users (id) ON DELETE SET NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE finding_triage IS
    'Current human decision about a finding. Independent of findings.status.';

CREATE INDEX finding_triage_state_idx ON finding_triage (state);

-- ---------------------------------------------------------------------------
-- triage_events — the append-only audit trail
-- ---------------------------------------------------------------------------

-- Every triage change, ever.
--
-- The same split as `findings` / `finding_occurrences` one migration earlier,
-- for the same reason: a table that holds only current state cannot answer
-- questions about the past. "This critical finding was suppressed, then
-- un-suppressed, then suppressed again by a different person the day before the
-- audit" is exactly the sequence a status column silently erases.
--
-- Append-only by convention and by shape: there is no column here that a later
-- event would ever need to update.
CREATE TABLE triage_events (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    finding_id     TEXT NOT NULL REFERENCES findings (id) ON DELETE CASCADE,

    -- NULL on the first event for a finding: there was no prior state.
    previous_state TEXT CHECK (
        previous_state IN ('untriaged', 'acknowledged', 'suppressed', 'false_positive')
    ),
    new_state      TEXT NOT NULL CHECK (
        new_state IN ('untriaged', 'acknowledged', 'suppressed', 'false_positive')
    ),
    note           TEXT,

    -- Who did it, recorded twice over, on purpose.
    --
    -- `actor_id` is the live foreign key, useful for joining while the account
    -- exists. `actor_email` is a denormalised copy that does not depend on that
    -- account continuing to exist. An audit trail that can be erased by
    -- deleting a user account is not an audit trail — and "delete the user,
    -- lose the evidence" is a plausible enough sequence that it is worth one
    -- text column to rule out.
    actor_id       BIGINT REFERENCES users (id) ON DELETE SET NULL,
    actor_email    TEXT NOT NULL,

    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE triage_events IS
    'Append-only log of every triage decision, including who made it.';

CREATE INDEX triage_events_finding_id_idx
    ON triage_events (finding_id, created_at DESC);
