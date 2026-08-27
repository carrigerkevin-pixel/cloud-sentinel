# CloudSentinel — Project Context
 
## What this is
A hybrid rule-based + ML-based Cloud Security Posture Management (CSPM) tool.
It audits a simulated AWS environment for misconfigurations, detects anomalous
behavior via ML, and presents findings in a dashboard. Built as a portfolio
project for summer 2027 CS internship applications (Georgia Tech, Cybersecurity thread).
 
Prior project (for context/style consistency): "Job Skills Trend Analyzer"
(Python, FastAPI, PostgreSQL, SQLAlchemy, Streamlit, Docker, GitHub Actions)
— https://github.com/carrigerkevin-pixel/job-skills-trend-analyzer
 
## Constraints
- **Must stay $0 cost.** No paid cloud resources, no paid tiers beyond free.
- Learning goal: get hands-on with TypeScript, Next.js, Node.js, Docker,
  Kubernetes — while working mainly through Claude Code.
- Security-first: this tool should itself follow good security practices
  (no hardcoded secrets, proper auth, etc.)
- **Every file must be properly documented** — see the documentation standard
  below. This is a hard requirement, not a nice-to-have.

## Code documentation standard
Every file in this repository must be understandable on its own, by someone
reading it for the first time — including me, months from now, and including a
reviewer skimming the public repo. This is a learning and portfolio project, so
comments carry more weight here than they would in ordinary production code.

Required in every source file:
1. **File header comment.** What this file is, why it exists, and where it fits
   in the CloudSentinel architecture (collector / rule engine / ML layer /
   dashboard). If it has a CLI or npm-script entry point, show the commands.
2. **Doc comments on every export.** Functions, types, classes, and constants
   that other files import get a comment describing what they do, what their
   parameters mean, what they return, and how they fail (thrown errors,
   `undefined` returns, partial results).
3. **Reasoning comments, not narration.** Explain *why* a non-obvious choice was
   made — a workaround, an ordering dependency, an AWS API quirk, a deliberate
   omission. Never write a comment that just restates what the line already
   says in code.
4. **Security rationale where it applies.** CloudSentinel is a security tool, so
   any code touching credentials, endpoints, permissions, auth, or intentionally
   insecure fixtures must state the risk and how the code handles it.
5. **Section dividers in long files.** Group related functions under banner
   comments so a long file can be navigated by scrolling.

Rule of thumb: if a reader would have to open a second file or search AWS docs
to understand why a line exists, that reason belongs in a comment.

## Working style with Claude Code
Claude explains each step in short plain language *before* doing it — what file
is about to be written or what command is about to run, and why — and then goes
ahead and does it. No writing first and explaining afterward.

Claude does **not** stop to ask for permission. That gate was in place through
phase 4 and has been lifted; the narration exists for comprehension, not as an
approval checkpoint.

The point is comprehension: I need to be able to follow and later defend every
design decision in this project in an internship interview.

## Tech stack
- **Frontend/API:** TypeScript, Next.js, Node.js
- **Database:** PostgreSQL (Docker container, local)
- **ML layer:** Python, scikit-learn (Isolation Forest or baseline stats model)
- **AWS emulation:** LocalStack (⚠️ now requires a free account + auth token
  as of March 2026 — see below)
- **Containerization:** Docker, Kubernetes (local via `kind` or `minikube`)
- **CI/CD:** GitHub Actions
## Architecture (planned)
1. **Collector service** (Node/TS) — pulls resource configs (S3, security
   groups, IAM) from LocalStack via AWS SDK
2. **Rule engine** — checks against CIS AWS Foundations Benchmark style rules
   (public S3 buckets, open security groups, permissive IAM policies, etc.)
3. **ML anomaly layer** (Python) — analyzes synthetic CloudTrail-style logs
   for behavioral anomalies (privilege escalation sequences, off-hours access,
   new-geo logins). Built in phase 6: an Isolation Forest plus a
   dependency-free statistical control, compared at an equal alert budget so the
   ML has to justify its place rather than being assumed to help.
4. **Dashboard** (Next.js/TS) — findings list, risk score, triage UI, JWT auth
## Current status (as of this handoff)
✅ Docker Desktop installed and working (virtualization issue resolved via
   Windows features, not BIOS — this machine's BIOS has no VT-x toggle exposed)
✅ Node.js v24.13.0 installed
✅ Next.js + TypeScript project scaffolded (`create-next-app`) at
   `C:\Users\carri\Documents\Projects\cloud-sentinel`
✅ Git repo initialized, pushed to
   https://github.com/carrigerkevin-pixel/cloud-sentinel
✅ AWS CLI v2 installed (`aws-cli/2.36.29`)
✅ LocalStack running successfully in Docker, authenticated with a free
   LocalStack account + `LOCALSTACK_AUTH_TOKEN` (required since LocalStack's
   March 2026 licensing change — the old no-account community image is gone)
✅ Working `awslocal` shortcut set up via a PowerShell profile function
   (the actual `awslocal` Python wrapper has a broken `pathlib` home-directory
   bug on this machine — the profile function `awslocal { aws --endpoint-url=http://localhost:4566 $args }`
   is the workaround in use instead of the pip-installed wrapper)

### Phase 1 complete — LocalStack fixtures
✅ `scripts/seed-localstack.ts` provisions intentionally-insecure resources
   plus a compliant control group, and tears them all back down. Idempotent.
   - `npm run seed` / `npm run seed:down` / `npm run seed:list`
   - 13 expected findings across a public S3 bucket, a security group open on
     tcp/22 and tcp/3389 (IPv4 and IPv6), an over-privileged IAM user with a
     console login and no MFA, and an IAM user who is an administrator *only*
     through group membership
   - Compliant controls (`cloudsentinel-private-logs`,
     `cloudsentinel-restricted-app`, `cloudsentinel-readonly-svc`) are clean
     under every planned rule, so they serve as a false-positive baseline
   - Teardown verified end to end: `seed:down` leaves nothing behind

### Phase 2 complete — collector service
✅ `lib/types/resource.ts` — normalized resource model. A discriminated union
   on `type`, so rules get compile-time narrowing of `config`. Records observed
   facts only; no compliance verdicts live in the collector.
✅ `lib/collectors/{s3,ec2,iam}.ts` — strictly read-only (`List`/`Get`/
   `Describe` only). Every resource carries an `unobserved` list naming settings
   that could not be read, so a rule can report *inconclusive* rather than
   mistaking a failed observation for a clean result.
✅ `scripts/collect.ts` — `npm run collect`, with `--json` and `--out <file>`.
   Runs all three collectors under one shared timestamp and exits non-zero if
   any collection error occurred.
✅ `lib/util/concurrency.ts` — bounded parallelism, default 8, tunable with
   `COLLECTOR_CONCURRENCY`. AWS clients use adaptive retry mode.
✅ `npm test` — 53 tests on Node's built-in runner. No test framework
   dependency, and no Docker or LocalStack needed to run them.
✅ `fixtures/inventory.json` — committed snapshot of a full scan, so the rule
   engine can be developed and tested offline. Regenerate with
   `npm run collect -- --out fixtures/inventory.json`.

### Phase 3 complete — rule engine
✅ `lib/rules/types.ts` — rule/finding vocabulary. A verdict has **three**
   states: `pass`, `fail`, and `inconclusive`. Inconclusive is first-class and
   is never rounded down to a pass, so an unreadable setting can never be
   reported as a clean result.
✅ `lib/rules/policy.ts` — shared IAM/S3 policy analysis: AWS wildcard
   matching, public-principal detection across all three spellings
   (`"*"`, `{AWS:"*"}`, `{AWS:["*"]}`), admin-statement detection, and stable
   per-statement keys. Deliberately not a full policy evaluator — it does not
   resolve Deny precedence, `NotAction`, or condition operators, and statements
   using those are reported as *inconclusive* rather than guessed at.
✅ `lib/rules/{s3,ec2,iam}.ts` — **12 rules** (6 S3, 1 security group emitting
   per-port/per-IP-family findings, 5 IAM). Every rule checks the resource's
   `unobserved` list before concluding anything from a `null` field.
✅ `lib/rules/engine.ts` — runs every rule over every resource. Deterministic
   finding ids (`<ruleId>|<resourceId>|<key>`) so a re-scan of an unchanged
   environment produces the same ids and the dashboard can later track a
   finding's lifecycle. A rule that throws becomes an inconclusive finding
   instead of killing the scan. Includes a saturating 0-100 risk score.
✅ `scripts/scan.ts` — `npm run scan`, plus `npm run scan:fixture`.
   Options: `--input <file>`, `--json`, `--out <file>`, `--severity <level>`,
   `--fail-on <level>`, `--rules`. Exit 0 clean / 1 threshold tripped or
   collection errors / 2 bad arguments.
✅ `lib/collectors/inventory.ts` — inventory assembly extracted from
   `scripts/collect.ts` so the collector and scanner CLIs share one definition
   of what a scan collects.
✅ **Verified**: all 13 `EXPECTED_FINDINGS` reproduce with exact title matches,
   the three compliant controls and the untouched `default` security group
   produce zero findings, and a live scan against LocalStack matches the
   committed fixture exactly. Risk score 87/100 (8 critical, 4 high, 2 medium).
   The engine finds one legitimate 14th finding the seeder does not list:
   `cloudsentinel-group-member` also inherits unrestricted `iam:PassRole` from
   the legacy-admins group's `iam:*` inline policy.
✅ `npm test` — **207 tests** (up from 53), still on Node's built-in runner
   with no test framework dependency and no Docker or LocalStack needed.

### CI
✅ `.github/workflows/ci.yml` — runs on push and PR to `main`: type-check,
   lint, full test suite, and a scanner run against the committed fixture.
   No secrets, `permissions: contents: read` only.

### Phase 4 complete — Postgres persistence
✅ `docker-compose.yml` — Postgres 17 container. Bound to `127.0.0.1` only, no
   default password (Compose aborts if `POSTGRES_PASSWORD` is unset), named
   volume so scan history survives a restart. `.env.example` is committed and
   carries no values; `.env` is gitignored.
✅ `db/migrations/0001_init.sql` — four tables. The design decision that matters:
   `findings` holds **one row per distinct problem** keyed by the engine's
   deterministic id, carrying `first_seen_at` / `last_seen_at` / `status`, while
   `finding_occurrences` records what each individual scan saw. That split is
   what makes "public since the 4th of August" answerable. A CHECK constraint
   enforces that a resolved finding has both a date and a reason, and an open
   one has neither.
✅ `lib/db/client.ts` — pooled connections, config from env. Refuses
   non-loopback hosts unless `CLOUDSENTINEL_ALLOW_REMOTE_DB=1`, requires TLS
   when remote, and never puts a credential in output or an error message.
   All queries are parameterised.
✅ `lib/db/migrate.ts` + `npm run db:migrate` / `db:status` — numbered
   migrations applied once each inside a transaction, tracked with a SHA-256
   checksum. Editing an already-applied migration is detected and refused.
   Advisory lock prevents two runners racing.
✅ `lib/db/lifecycle.ts` — **pure function**, no SQL, so the risky logic is
   testable with no database. Decides created / continuing / reopened /
   resolved / unverified. Resolution requires: no collection errors, and either
   the resource is gone (`resource_removed`) or the resource was inspected and
   the rule stayed quiet (`fixed`). Absence is never treated as proof.
✅ `lib/db/scans.ts` + `npm run scan -- --save` — writes the scan, its
   resources, and finding occurrences in one transaction. `first_seen_at` is
   never overwritten on re-scan.
✅ `npm test` — **226 tests**, still no database required.
✅ `npm run test:db` — **12 integration tests** against a real Postgres. They
   create and drop their own `cloudsentinel_dbtest` database, so the dev
   database is never touched. CI runs them against a service container.
✅ **Verified end to end** against live LocalStack: first save creates 14
   findings; re-saving the same inventory creates none and adds occurrences;
   remediating the public bucket resolves exactly its 5 findings as `fixed`;
   reverting reopens them with the original `first_seen_at` intact; and a scan
   with collection errors resolves **nothing**, holding all 14 open.
 
### Phase 5 complete — dashboard, API, and auth
✅ `db/migrations/0002_dashboard.sql` — three tables. `users` (scrypt hash,
   two roles, `token_version`), `finding_triage` (current human decision), and
   `triage_events` (append-only log of every change). The design decision that
   matters: **triage never touches `findings.status`**. `open`/`resolved` stays
   the scanner's claim about reality; triage is the human overlay. Suppressing a
   finding hides it from the default view and changes nothing about whether the
   bucket is still public. A CHECK constraint requires a written justification
   for any state other than `untriaged`.
✅ `lib/auth/password.ts` — scrypt (N=16384), per-user salt, cost parameters
   stored inside the hash so they can be raised later without locking anyone
   out. Constant-time comparison. Exports `DECOY_PASSWORD_HASH`, verified
   against when no account matches, so an unknown email costs the same as a
   known one and the login form cannot be used to enumerate accounts.
✅ `lib/auth/jwt.ts` — HS256 sign/verify written directly on `node:crypto`, no
   library. The algorithm is decided by the code and never read from the token,
   so `alg: none` and algorithm-confusion forgeries are rejected. Signature is
   checked *before* any claim is trusted.
✅ `lib/db/users.ts` + `npm run user:create|list|passwd|revoke|delete` — there
   is no sign-up page; accounts exist only via the CLI, and the password is
   prompted for with echo suppressed rather than passed as an argument (which
   would land in the shell history and the process list).
✅ **Revocation.** A JWT cannot normally be recalled before it expires.
   `users.token_version` is embedded as a claim and compared on every request,
   so `npm run user:revoke` kills every token for an account immediately.
   Changing a password or a role bumps it too — a demoted admin loses admin
   access on their next request, not whenever their token happens to expire.
✅ `lib/auth/session.ts` — the token rides in an `httpOnly`, `SameSite=strict`
   cookie, `Secure` in production. Not `localStorage`: an XSS flaw can read
   `localStorage` and exfiltrate a session, but cannot read an httpOnly cookie.
✅ `lib/api/http.ts` — `requireUser()` / `requireAdmin()` guards returning a
   discriminated union, so TypeScript refuses to let a route reach `user`
   without handling the failure. Guards live in the routes rather than
   middleware, because the Edge runtime has neither `node:crypto` nor a
   database connection and a middleware check would have to trust the token's
   own claims.
✅ `lib/api/rate-limit.ts` — fixed-window limiter on the login route, 10
   attempts per 15 minutes per client. Checked before the body is parsed, since
   each scrypt verification costs the server ~100 ms and an unthrottled login
   endpoint is a denial-of-service amplifier. Its limitations (in-process,
   resets on restart, trusts `x-forwarded-for`) are documented in the file.
✅ `app/api/` — `auth/login`, `auth/logout`, `auth/session`, `findings`,
   `findings/[id]`, `findings/[id]/triage`, `scans`, `summary`. Reads need any
   signed-in user; the only state-changing route needs an admin.
✅ `lib/api/finding-id.ts` — finding ids embed ARNs and therefore contain
   forward slashes, so they cannot go in a URL path segment. They are
   base64url-encoded for URLs and validated on the way back, including a
   rejection of control characters.
✅ `app/(app)/` — the dashboard: overview (risk score, severity breakdown,
   recent scans), findings list with URL-driven filters, finding detail with
   full occurrence history and the triage control, and scan history. Server
   components querying Postgres directly; the layout re-verifies the session
   before any child page renders.
✅ **Suppression can never improve the headline number.** The overview reports
   the filtered count *and* the true total *and* how many are hidden. A risk
   score that dropped when you clicked "suppress" would reward hiding problems
   rather than fixing them.
✅ `npm test` — **285 tests** (up from 226), still no database required. Roughly
   two thirds of the JWT suite is forgery attempts.
✅ `npm run test:db` — **58 integration tests** (up from 12), across three
   `.dbtest.ts` files that each create and drop their own database (different
   names, because `node --test` runs files concurrently).
✅ CI now runs `npx next build` as well as the type-check. This caught a real
   bug the type-checker could not: a client component imported a value from
   `lib/db/triage.ts`, so the bundler tried to put the PostgreSQL driver into a
   browser bundle. The triage vocabulary now lives in `lib/types/triage.ts`,
   which imports nothing that reaches the database.
✅ **Verified end to end** against the running dev server: unauthenticated
   pages redirect to `/login` and every API route answers 401; a tampered
   payload, an `alg: none` forgery, and a token signed with the wrong secret are
   all rejected; revoking sessions and demoting a role each kill a live cookie
   mid-session; the rate limiter blocks the 11th attempt with `Retry-After`; a
   viewer gets 403 on triage and never sees the control, while still being able
   to read who suppressed what.

### Phase 6 complete — ML behavioural anomaly layer
The rule engine answers *"what is configured wrongly?"*. This phase answers a
different question — *"who is behaving strangely?"* — because an intruder using
stolen but legitimate credentials changes no configuration at all, so no rule
can see them.

**Synthetic data (TypeScript)**
✅ `lib/util/random.ts` — seeded PRNG (mulberry32 + FNV-1a). Determinism is a
   hard requirement, not a nicety: thresholds tuned against data that changes
   underneath you are guesses, and a flaky detector test trains you to ignore it.
✅ `lib/types/cloudtrail.ts` — CloudTrail event model and the ground-truth label
   type. **A cross-language contract**: `ml/features.py` parses these field names
   and Python cannot type-check against TypeScript, so a test in
   `lib/logs/generator.test.ts` asserts they still exist.
✅ `lib/logs/generator.ts` — six principals across 30 days, ~36,500 events, with
   **five labelled attacks**: `credential_abuse`, `privilege_escalation`,
   `new_geo_login`, `off_hours_access`, `data_exfiltration`. Each principal gets
   its own generator seeded from its ARN, so adding a persona changes only that
   persona's events instead of rewriting the whole log.
   - **Two control principals**, the same role the compliant buckets play in
     phase 1: `cloudsentinel-backup-service` runs 24/7 with a heavy 02:00 batch,
     and `dave-admin` performs sensitive IAM writes as his ordinary job. Both
     must come out clean. They are the false-positive baseline, and they are
     what forces per-principal rather than account-wide modelling.
   - Every address is from the RFC 5737 documentation ranges and the account id
     is AWS's `123456789012` placeholder — a public repo must never appear to
     accuse a real IP of credential theft.
✅ `scripts/gen-logs.ts` — `npm run logs:gen`, with `--seed`, `--days`,
   `--no-attacks`, `--summary`.
   - **The log is generated, not committed** — the opposite of
     `fixtures/inventory.json`, and deliberately so. That file needs LocalStack
     to reproduce; this one is pure computation, deterministic, and takes 190ms,
     so committing 27MB that any checkout can rebuild would bloat every clone.
     CI regenerates it.
   - Events and labels go to **separate files**. The detector never opens the
     label file; only `ml/evaluate.py` does, after detection has finished. That
     is a structural guarantee that an unsupervised model cannot train on the
     answer key, which is worth far more than a comment asking people not to.

**Models (Python, `ml/`)**
✅ `ml/features.py` — 14 features per principal-hour. Every one is a *ratio* or a
   *rarity*, never an absolute: the question is never "is this a lot?" but "is
   this a lot **for this principal**?" Three techniques carry the file:
   - **Leave-one-window-out profiling.** The attacks are in the data, so each
     window is scored against the principal's history *excluding itself* — done
     by subtracting the window's own contribution from a single aggregate, so it
     stays one pass instead of quadratic.
   - **Hour-of-day-relative volume.** Found empirically, and the single most
     important fix in the phase. The first version divided by the principal's
     overall median, which flagged the backup role's 02:00 batch on nearly every
     night of the month. Comparing an hour against *the same hour on other days*
     removed the entire class of false positive.
   - **Empirical-Bayes shrinkage** on every rate. A four-call hour with one
     failure has a 25% error rate, which against a 1% background looks like a
     catastrophe and is one stale script. Shrinking toward the principal's own
     prior damps small windows while leaving real signal intact — this alone
     took Isolation Forest recall from 60% to 80%.
✅ `ml/baseline.py` — a dependency-free statistical control: per-principal robust
   z-scores (median/MAD, 50% breakdown point so the attacks cannot mask
   themselves), winsorised at 25σ, summed over the worst three features. It
   exists to answer the question nobody usually asks — **does the ML actually
   earn its place?**
✅ `ml/detect.py` — scikit-learn `IsolationForest`, fixed `random_state`.
   - Both models get the **same alert budget**, so the comparison measures which
     spends a fixed amount of human attention better rather than which alerts
     more. `--contamination` is therefore a staffing decision, not an estimate
     of how much intrusion is present.
   - **Evidence comes from the baseline.** A forest score is an average path
     length and cannot be attributed to any one feature, so the forest decides
     *what* to flag and the statistical model explains *why* it is unusual. The
     dashboard says exactly that rather than implying the forest reasoned so.
✅ `ml/evaluate.py` — the only module permitted to read the labels. Matches
   detections to attacks by **event-id intersection**, not by timestamp overlap,
   which would flatter the result.
✅ `npm run ml:setup | ml:features | ml:detect | ml:evaluate | ml:pipeline`, via
   `scripts/ml.ts` — a launcher that finds `.venv/Scripts` on Windows and
   `.venv/bin` on the CI runner, and only ever executes an allowlisted script.

**The headline result** (30 days, 1,990 windows, 20 alerts per model):

| | recall | control false positives | most repeated alert |
|---|---|---|---|
| Isolation Forest | 80% (4/5) | 10 | dave-admin ×7 (35%) |
| Statistical baseline | 80% (4/5) | 13 | **backup-service ×12 (60%)** |

Both find four of five. **The ML does not win on recall — it wins by repeating
itself less.** The statistical model spends twelve of its twenty alerts
re-reporting the same nightly cron job, because a per-feature threshold has no
notion of recurrence; the forest spends three, because thirty near-identical
batch windows form a dense cluster and are not *isolated*. That is the
difference between a tool somebody keeps reading and one they mute in week two,
and a muted detector's real recall is zero whatever its recall column says.

`off_hours_access` is missed by both, **by design**. It is the deliberately weak
scenario — ordinary work, usual address, usual region, only the clock is wrong —
included to test whether a single weak signal is enough. It is not, and
`ml/evaluate.py` reports that rather than tuning until it disappears.

⚠️ Every figure above comes from synthetic data generated by this project's own
rules, so the models are partly tested against the generator's assumptions. They
demonstrate the pipeline works end to end; they are **not** a claim about
accuracy on a real AWS account. The evaluation prints this caveat itself so the
number cannot be quoted without it.

**Persistence and dashboard**
✅ `db/migrations/0003_anomalies.sql` — `anomaly_runs` + `anomalies`. The design
   decision that matters: **anomalies have no lifecycle.** A finding is a
   condition that persists until fixed, which is why `findings` carries
   `first_seen_at` and `status`. An anomaly is an observation about one past
   hour — it cannot be fixed and cannot recur, because a later strange hour is a
   *different* hour. Copying the findings design here would have looked
   consistent and been wrong.
✅ `lib/anomalies/ingest.ts` — full validation of the detections file, unlike
   `scripts/scan.ts` which deliberately trusts its input. Three things differ:
   the producer is in another language TypeScript cannot check, the data lands
   in a database and then a browser, and trust rests on a file path rather than
   a call.
✅ `lib/db/anomalies.ts`, `scripts/anomalies.ts` — `npm run ml:save`, `ml:runs`.
   All database access stays in TypeScript so the connection and TLS rules in
   `lib/db/client.ts` exist in exactly one place.
✅ `app/(app)/anomalies/` — list and detail pages. Both models' scores are always
   shown, because **disagreement is the informative part**; the detail page shows
   all fourteen features including the thirteen that were ordinary, since what
   did *not* happen matters as much as what did.
✅ CI runs the whole pipeline with `--require-recall 0.6` as a regression gate,
   and stores the detections in Postgres to exercise migration 0003.
✅ `npm test` — **369 tests** (up from 285), still no database, no Docker and no
   Python required.
✅ `npm run test:db` — **76 integration tests** (up from 58). The new file is
   `lib/db/anomalies.dbtest.ts`, on its own `cloudsentinel_anomtest` database —
   `node --test` runs files concurrently, so a shared name would let two suites
   truncate each other's tables mid-assertion. It covers what the pure ingest
   tests cannot: that the `TEXT[]` and `JSONB` columns round-trip, that
   `NUMERIC` scores come back as numbers rather than strings (`"99.95" >
   "100.00"` is true in string comparison, which would sort the dashboard
   wrongly), and that a failed insert rolls the entire run back.

### Phase 7 complete — containers and Kubernetes
The project now deploys as containers into a local Kubernetes cluster. Nothing
about the application changed to make that possible except one thing, described
below, and that one thing was a deliberate refusal to weaken an existing rule.

**Images (`Dockerfile`)**
✅ Multi-stage, producing **two runtime images** from one source tree, plus a
   throwaway `certgen` stage.
   - `cloudsentinel:app` — the standalone Next.js server. 317MB.
   - `cloudsentinel:tools` — `scripts/`, `lib/`, `db/migrations/`. 564MB.
   - The split is least privilege, not tidiness: the dashboard image **cannot**
     migrate the database, create an admin user, or call AWS, because `scripts/`
     and the AWS SDK are not in it. A compromised web process has no
     `node scripts/user.ts create --admin` available to it.
✅ `output: "standalone"` in `next.config.ts` — Next traces what the server
   actually imports, taking the application payload from a 500MB `node_modules`
   tree to 31MB. Static assets are **not** traced (nothing imports them) and are
   copied explicitly; miss that and the site renders completely unstyled.
✅ The `tools` stage deletes Next, React, `sharp` and the SWC binaries after
   `npm ci --omit=dev` — 384MB of web framework that no CLI imports, and which
   would otherwise hand an intruder a compiler in a migration container. They
   survive `--omit=dev` because they are production dependencies *of the
   dashboard*, which npm has no way to know this image never serves. A
   build-time check imports the whole CLI module graph so a future import that
   reaches React fails the build rather than a deployment.
✅ The build-time `CLOUDSENTINEL_JWT_SECRET` is a placeholder scoped to a single
   `RUN` command rather than an `ENV`. It reaches no layer, no image metadata,
   and no runtime image — and it avoids Docker's own linter correctly reporting
   a secret in the environment.

**The one application change, and why it went the way it did**
`lib/db/client.ts` has always required certificate-verified TLS for any
non-loopback database. In a cluster the database is `cloudsentinel-db`, so that
rule applies to **every** connection — and the first deployment failed with
`The server does not support SSL connections`, exactly as designed.

The tempting fix is a switch that skips verification for "internal" hosts. That
was rejected. It yields a connection that is encrypted but *unauthenticated*, so
anything able to answer on the Service address can terminate and read it — and
the traffic is scan findings, which are a ranked list of where an environment is
weakest. A tool that reports other people's weak configurations must not ship
the habit it criticises.

So the rule is **satisfied** instead:
✅ `resolveSslOptions()` + `POSTGRES_CA_CERT_FILE` — supply the authority that
   signed the certificate and keep `rejectUnauthorized: true`. There is
   deliberately no setting anywhere in the project that disables verification.
   A missing CA file is a hard failure, because falling back to the system trust
   store would silently widen what is accepted from one private CA to every
   authority on the internet, and nothing would look wrong.
✅ `scripts/k8s.ts` issues a private CA and a server certificate whose Subject
   Alternative Names cover all four spellings of the Service hostname.
✅ Six tests in `lib/db/client.test.ts`, weighted toward "can verification be
   turned off by any route" rather than the happy path — the dangerous failure
   is silent.

**Manifests (`k8s/`)**
✅ `00-namespace.yaml` — enforces the **restricted Pod Security Standard** at the
   namespace. The API server rejects any pod running as root, escalating
   privileges, keeping capabilities, or missing a seccomp profile. Declared here
   rather than trusted to each manifest because a `securityContext` is a promise
   a manifest makes about itself, and a dropped promise produces no complaint.
✅ `10-postgres.yaml` — StatefulSet, TLS on, `readOnlyRootFilesystem`, uid 70
   (the Alpine `postgres` account — the Debian image uses 999). The
   `volumeClaimTemplate` survives deletion of the StatefulSet, so removing the
   workload does not destroy `first_seen_at`, the one value in the project that
   cannot be regenerated.
✅ `20-migrate-job.yaml` — migrations as a Job, not on application startup. Two
   reasons: two replicas would race the schema, and more importantly
   `ALTER TABLE`/`DROP` is the ability to destroy every stored finding, which a
   long-running web process should not hold for its whole lifetime because it
   needed it for two seconds at boot.
✅ `30-app.yaml` — Deployment of 2 replicas, `maxUnavailable: 0`, NodePort 30080.
   Two replicas is the smallest number that proves anything: with one, a rolling
   update is an outage and the readiness gate is never tested.
✅ `40-networkpolicy.yaml` — default-deny ingress, plus the connections actually
   needed. Database access is gated on a **capability label**
   (`cloudsentinel.dev/db-client`) rather than a list of workload names. Both
   were tried; the list was wrong, and it failed exactly as predicted — the
   account-creation pod was not on it and hung on a connection timeout with
   nothing pointing back at the policy. Egress from the dashboard is restricted
   to DNS and the database, so a compromised web process has no route off the
   machine at all.
✅ `kind-cluster.yaml` — single node, NodePort 30080 published on **127.0.0.1
   only**. The default `0.0.0.0` would publish the login form to every network
   this laptop is attached to; that is the same loopback discipline
   docker-compose.yml and lib/db/client.ts already apply.

**Probes**
✅ `app/api/healthz` (liveness) and `app/api/readyz` (readiness) — split
   deliberately. Failing liveness *restarts* the container, so it must only fail
   for something a restart fixes; if it queried Postgres, a database outage would
   restart every replica in a loop and hit the recovering database with a
   thundering herd. Readiness owns the database check, and failing it merely
   parks the pod. Both are unauthenticated and therefore disclose nothing: the
   readiness failure body is the fixed string `{"status":"unready"}`, with the
   driver error — which names the host, user and precise authentication failure
   — logged server-side only.

**`scripts/k8s.ts`**
✅ `npm run k8s:cluster | build | up | user | status | logs | down`. It exists
   because `kubectl apply -f k8s/` cannot order the stages, cannot generate
   secrets, and fails on re-run because a Job's spec is immutable.
✅ Secrets are piped to `kubectl` over **stdin**, never `--from-literal`: a
   command line is world-readable in the process list and lands in shell
   history. Same reasoning as `npm run user:create` prompting for a password.
✅ Four separate secrets, so the database gets the server key while the clients
   get only the public CA — anything holding that key could impersonate the
   database.
✅ `k8s:down` keeps the volume and the secrets; only `--purge` deletes data.

**Verified end to end against a real kind cluster (Kubernetes 1.37)**
- All three migrations applied; both dashboard replicas connected over
  **TLSv1.3 / AES-256-GCM**, which — with `rejectUnauthorized: true` and the
  private CA — means certificate and hostname verification genuinely succeeded.
- Dashboard reachable at `http://localhost:30080`; `/api/findings` returns 401
  unauthenticated, `/` redirects to `/login`, and the CSS loads (proving the
  manual `.next/static` copy in the Dockerfile is right).
- **NetworkPolicy is genuinely enforced on kind**: a probe pod without the
  `db-client` label times out reaching the database, while the dashboard remains
  reachable. The dashboard cannot open a connection to `1.1.1.1:443` but can
  reach the database.
✅ CI (`containers` job) — builds both images on Linux, smoke-tests them against
   a real Postgres, then creates a kind cluster, runs `npm run k8s:up`, and
   **asserts the controls are live**: `k8s/test/netpol-probe.yaml` must report
   BLOCKED and `pg_stat_ssl` must report encrypted client connections. A
   NetworkPolicy that is stored but inert looks identical to one that works.
✅ `npm test` — **375 tests** (up from 369), still no database, Docker or Python.

### Phase 8 complete — security hardening, docs, demo script
The final phase. The starting point was a survey rather than a checklist: `npm
audit` was already clean, no `dangerouslySetInnerHTML` or `eval` existed
anywhere, and nothing secret-shaped had ever been committed (only
`.env.example`). Three genuine gaps came out of it — **no security response
headers at all**, **no CSRF defence beyond the SameSite cookie**, and **no
disclosure policy** — and those are what this phase fixed.

**Response headers**
✅ `next.config.ts` — the headers with no per-request component:
   `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
   `Permissions-Policy`, `Strict-Transport-Security`, and the two Cross-Origin
   isolation headers. `poweredByHeader: false` drops `X-Powered-By`.
   - `Referrer-Policy` matters more here than on an ordinary site: a finding
     detail URL contains a base64url-encoded finding id, which encodes the ARN
     of a misconfigured resource. A leaked referrer names a currently-public
     bucket.
   - HSTS is inert over plain HTTP by design, so it is correct-but-dormant on
     the NodePort and becomes active the moment TLS is in front. `preload` is
     omitted deliberately — it is close to irreversible.
✅ `proxy.ts` — a per-response CSP nonce. (Named `proxy.ts`, not
   `middleware.ts`: Next 16 renamed the convention, and the old spelling logs a
   deprecation warning on every build.)
   - A nonce rather than `'unsafe-inline'`, because `'unsafe-inline'` permits
     every inline script — which is exactly what an injected `<script>` is — so
     a policy containing it looks like a control and is not one.
   - Minting a nonce needs only `crypto.getRandomValues` and reads nothing about
     the requester, so this does **not** reopen the phase 5 decision to keep
     auth guards out of middleware. That reasoning (no `node:crypto`, no
     database on the Edge runtime) still holds and is restated in the file.
   - `'strict-dynamic'` so Next's bootstrap can load its own hashed chunks
     without enumerating URLs that change every build.
   - `style-src` keeps `'unsafe-inline'` — Next emits unnonced inline styles for
     critical CSS and `next/font`. Documented as the narrower compromise it is:
     CSS injection is real but a long way short of script execution.

**The bug that only testing caught**
The first working CSP served a **blank dashboard**, and nothing in the build or
the type-check said so. `/login` and `/_not-found` were statically prerendered,
so their HTML — including Next's inline bootstrap script — was generated at
build time, long before any nonce existed. Those scripts went out unmarked and
the policy refused them. The page returns 200 and looks perfect in `curl`.

Fixed with `export const dynamic = "force-dynamic"` on the root layout, which
costs this application nothing: every other route already reads Postgres per
request, and the login page is a form with nothing to cache. Verified by
asserting all ten script tags carry the nonce and that the header nonce matches
the one in the HTML.

**Cross-site request forgery**
✅ `checkSameOrigin()` in `lib/api/http.ts`, applied to all three
   state-changing routes (login, logout, triage).
   - Compares `Origin` against the request's own `Host`, so it is correct on
     localhost, on the NodePort, and behind a domain with no configuration to
     keep in step.
   - A **missing** `Origin` is rejected. Browsers always send it on these
     requests, so absence means the caller is not one; allowing it would leave
     an opt-out consisting of not sending a header.
   - It is a second layer behind `SameSite=strict`, and it covers three real
     gaps: a client that does not implement SameSite, a *same-site* attacker on
     a sibling subdomain (SameSite uses the registrable domain, `Origin` does
     not), and a future relaxation to `SameSite=lax`.
✅ 13 tests, weighted toward the ways an origin check is usually written wrong —
   substring comparisons that accept `evil-cloudsentinel.test` and
   `cloudsentinel.test.attacker.test`, `Origin: null` from a sandboxed iframe,
   and reflecting the rejected value back into the response.

**A module split that had to happen**
`lib/api/http.ts` could not be tested at all: importing it pulled
`lib/auth/session.ts` and therefore `next/headers`, which does not resolve
outside a Next server, so the whole suite failed to load. The session guards
moved to `lib/api/guards.ts`, leaving `http.ts` pure.

Worth recording because the **first attempt was wrong**: `http.ts` re-exported
the guards "for convenience", which silently undid the entire split — a
re-export is still an import, so `next/headers` came straight back and the tests
failed identically. A module boundary that exists to keep a dependency out
cannot also forward that dependency. The six route files now import guards
directly. This is the mirror image of the phase 5 bug where a client component
imported from `lib/db/triage.ts` and the bundler tried to put the PostgreSQL
driver in a browser bundle.

**Supply chain**
✅ `npm audit --omit=dev --audit-level=high` in CI. `--omit=dev` is load-bearing:
   an advisory against ESLint or TypeScript is not a vulnerability in the
   deployed application, and a gate that must routinely be overridden is not a
   gate.
✅ Trivy image scanning, run from Trivy's own image rather than a marketplace
   action, and fed a `docker save` tarball rather than a mounted Docker socket —
   the socket would grant the scanner root-equivalent control of the host daemon
   purely so it can read a filesystem layer.
   - Two steps: a MEDIUM-and-above report that never fails, and a gate on
     `CRITICAL` **with a fix available**. A critical with no published fix cannot
     be acted on, and a red build nobody can clear trains people to ignore it.
✅ The gate immediately found one: a fixable CRITICAL (CVE-2026-59873) in the
   `tar` copy vendored inside npm in the Node base image.
   **Fixed by deleting npm from both runtime images** rather than chasing
   upstream's patch cadence. Neither needs it — `app` runs `node server.js`,
   `tools` runs `node scripts/*.ts` — and npm is a program whose purpose is
   fetching and executing remote code, which is precisely what an intruder in a
   container wants. Same argument that keeps `scripts/` and the AWS SDK out of
   the dashboard image, applied to the base image's own tooling.

**Documentation**
✅ `SECURITY.md` — disclosure process (GitHub private advisories, deliberately
   not a personal email address on a public repo), scope including what is
   explicitly *out* of scope (the intentionally-insecure fixtures are the point,
   not a bug), an adversary/defence threat-model table, and a known-limitations
   list.
✅ README — a Security section with a control summary table, and the two
   consequences that affect anyone using the API by hand (`Origin` required on
   writes).
✅ `docs/demo.md` — a six-minute walkthrough script, structured around four
   decisions rather than a feature tour, with a three-minute cut-down. Includes
   a recording checklist with the explicit warning not to show `.env`,
   `k8s/tls/`, or `kubectl get secret -o yaml` on camera.

**Verified**
- All headers present through the Kubernetes NodePort on the redeployed images.
- CSRF guard live in-cluster: no Origin → 403, attacker Origin → 403, correct
  Origin → 401 (reaches the authentication path), `GET` unaffected.
- Every script tag nonced; the nonce rotates per response.
- Both images pass the fixable-CRITICAL gate after npm removal, and the `tools`
  image's CLI module graph still loads.
✅ `npm test` — **388 tests** (up from 375).

### Getting the dashboard running
```
docker compose up -d db
npm run db:migrate
npm run user:create -- you@example.com --admin   # prompts for a password
npm run scan -- --save                           # needs LocalStack + npm run seed
npm run dev                                      # http://localhost:3000
```

### Getting the anomaly layer running
```
npm run ml:setup      # creates ml/.venv, installs numpy + scikit-learn (once)
npm run ml:pipeline   # generate logs -> detect -> evaluate
npm run ml:save       # store the run so /anomalies can show it
```
Needs Python 3.11+ on PATH. Nothing here touches AWS, LocalStack or the network.
`CLOUDSENTINEL_JWT_SECRET` must be set in `.env` — see `.env.example`. There is
no default, and `lib/auth/jwt.ts` refuses to start without one.

### Getting it running on Kubernetes
```
npm run k8s:cluster                          # create the kind cluster (once)
npm run k8s:build                            # build both images, load them in
npm run k8s:up                               # deploy in dependency order
npm run k8s:user -- you@example.com --admin  # prompts for a password
                                             # then http://localhost:30080
```
`npm run k8s:status` / `k8s:logs` to inspect it. `npm run k8s:down` removes the
workloads but keeps the database volume and the secrets; only
`npm run k8s:down -- --purge` deletes the data. Nothing here needs LocalStack —
the dashboard reads the database, not AWS.

## Environment notes specific to this machine
- OS: Windows, PowerShell as primary shell
- Python installed at `C:\Users\carri\AppData\Roaming\Python\Python314\`
  (user-level pip installs land in `...\Python314\Scripts` — this had to be
  added to PATH manually)
- The ML layer does **not** use that global Python's packages. `npm run ml:setup`
  creates a project-local virtual environment at `ml/.venv` and installs
  `ml/requirements.txt` into it. The venv is gitignored and disposable — delete
  it and re-run setup. `scripts/ml.ts` locates the interpreter on either OS, so
  the venv never has to be activated by hand.
- scikit-learn 1.9.0 and NumPy 2.5.2 publish cp314 wheels, so Python 3.14 on
  this machine installs them without needing a build toolchain. CI pins 3.13.
- ESLint is configured to ignore `ml/.venv/**`: scikit-learn ships notebook
  JavaScript that would otherwise be linted and reported on every run.
- Python writes to a cp1252 console here, and raises `UnicodeEncodeError` rather
  than substituting when it cannot encode a character. `scripts/ml.ts` sets
  `PYTHONIOENCODING=utf-8`, and the Python reports avoid non-ASCII output
  anyway — a stray `σ` crashed a run *after* all the work was done.
- PowerShell execution policy set to `RemoteSigned` for `CurrentUser` scope
  (needed for `npx` to run)
- `kind` was installed with `winget install Kubernetes.kind` (v0.33.0). winget
  adds it to the user PATH, so **a shell started before the install will not see
  it** — open a new terminal, or call it at
  `%LOCALAPPDATA%\Microsoft\WinGet\Packages\Kubernetes.kind_*\kind.exe`.
  `kubectl` was already present: Docker Desktop ships it.
- Docker Desktop's built-in Kubernetes is the alternative to kind and
  `scripts/k8s.ts` supports it, but it does **not** enforce NetworkPolicy, so
  `k8s/40-networkpolicy.yaml` is stored and inert there. `npm run k8s:up` prints
  a warning when it detects that cluster. kind enforces it — verified.
- AWS CLI dummy credentials configured (`test`/`test`/`us-east-1`) — LocalStack
  doesn't validate real credentials, just needs something present
- LocalStack runs with **persistence disabled**, so all seeded fixtures are lost
  whenever the container restarts. Re-run `npm run seed` after starting it.
- The Git Bash shell does not pick up the AWS CLI's configured default region.
  Ad-hoc `aws` commands from Bash need `--region us-east-1` explicitly, or
  `AWS_REGION` exported; PowerShell is unaffected.
- **`package-lock.json` must be generated on Linux, not on Windows.** Running
  `npm install` on this machine silently drops the `@emnapi/core` and
  `@emnapi/runtime` entries that `@tailwindcss/oxide-wasm32-wasi` depends on.
  The result installs fine locally but makes `npm ci` fail on `ubuntu-latest`
  with "Missing: @emnapi/core@... from lock file", which breaks CI at the very
  first step. After any dependency change, regenerate the lockfile with
  `npm run relock` (runs `npm install --package-lock-only` inside a
  `node:24-slim` container via Docker) and commit that version. Do not run a
  plain `npm install` afterwards, or it will strip the entries again.
## Not started yet (next steps)

All eight phases are code-complete, committed, and pushed, and CI is green on
`main`. What remains is a short list of things that **cannot be done by an
agent** — they need a real terminal, a real browser, a microphone, or the GitHub
web UI. They are listed here in the order it makes sense to do them.

### Manual steps outstanding

**1. Open a fresh terminal before anything else.**
`kind` was installed during phase 7 with `winget install Kubernetes.kind`
(v0.33.0). winget adds it to the user PATH, but a shell started *before* the
install will not see it. If `kind version` fails, that is why — open a new
terminal rather than debugging it. `kubectl` is unaffected; Docker Desktop
ships it.

**2. Create a dashboard account, and log in to a browser.**
```
npm run k8s:user -- you@example.com --admin      # in the cluster
npm run user:create -- you@example.com --admin   # or against local Postgres
```
This **must be run in a real interactive terminal**. `scripts/user.ts` prompts
for the password with echo suppressed, which requires a TTY, so it cannot be
piped or scripted — that is deliberate (an argument would land in shell history
and the process list), not a limitation to work around.

**3. Verify the authenticated pages render under the new CSP.** ← *the real gap*
This is the one genuinely unverified thing in the project, and it is worth doing
before recording anything.

Phase 8 added a nonce-based Content Security Policy. What *was* verified: every
script tag on the login page carries the nonce, the nonce rotates per response,
the header matches the HTML, and all the security headers survive the Kubernetes
NodePort. What was **not** verified is any page behind the login, because
creating an account needs the TTY in step 2.

So open http://localhost:30080 (or :3000), sign in, and walk every page —
overview, findings list, a finding detail, anomalies, scans — with the browser
devtools **console open**, watching for `Content Security Policy` violation
messages. Pay particular attention to the two client components,
`app/components/TriageControl.tsx` and `LogoutButton.tsx`, since interactive
components are where a CSP problem would surface. Actually click *suppress* on a
finding and confirm the triage flow completes.

A CSP failure here is silent in the terminal and obvious in the console, which
is exactly why it needs a human with a browser. If something is blocked, the
policy is in `proxy.ts` and each directive is annotated with why it is there.

**4. Enable private vulnerability reporting on the repository.**
`SECURITY.md` links to
`https://github.com/carrigerkevin-pixel/cloud-sentinel/security/advisories/new`,
which only works once the feature is switched on:
**Settings → Advanced Security → Private vulnerability reporting → Enable**.
Until then the link 404s, which looks worse than having no policy at all.

**5. Record the demo video.**
`docs/demo.md` is the full script — six minutes, with a three-minute cut-down
at the end, structured around four decisions rather than a feature tour.

Read its "Before recording" section first: it lists the setup commands and a
checklist. The two items worth repeating here:
- **Do not show `.env`, `k8s/tls/`, or `kubectl get secret -o yaml` on camera.**
  Those hold the real signing key and database password for this machine. A demo
  of a security tool leaking its own credentials is what a reviewer remembers.
- LocalStack runs with persistence disabled, so **re-run `npm run seed`** after
  starting its container or the scanner section will find nothing.

### State of the machine as of this handoff

- The **kind cluster is still running** (`cloudsentinel`), with the hardened
  phase 8 images loaded and deployed: two dashboard replicas, Postgres, and the
  completed migration Job. `npm run k8s:status` to check.
- `npm run k8s:down` removes the workloads but keeps the database volume, the
  secrets, and the generated TLS material, so `npm run k8s:up` brings it all
  back unchanged. Only `npm run k8s:down -- --purge` deletes the data.
- The Compose Postgres (`cloudsentinel-db`) is also up, separate from the
  cluster's own database.
- `k8s/tls/` holds a generated CA and server certificate. It is gitignored.
  Deleting the directory forces new ones on the next `k8s:up`, but the existing
  Secrets are not regenerated automatically — if the TLS material is ever
  replaced, delete the `cloudsentinel-db-tls` and `cloudsentinel-ca` Secrets too
  or the database will present a certificate the clients no longer trust.
- Nothing is uncommitted. `main` is pushed and CI is green.

Known follow-ups, none blocking:
- **`style-src` still allows `'unsafe-inline'`.** Next emits unnonced inline
  styles for critical CSS and `next/font`, so a strict style policy would break
  rendering. Closing it needs either nonced style tags from Next or moving those
  declarations into a stylesheet.
- **The `Origin` check trusts `Host`.** Behind a reverse proxy that forwards an
  attacker-chosen Host, it would be bypassable — the same trust assumption
  `lib/api/rate-limit.ts` documents for `x-forwarded-for`.
- **Trivy's gate is `CRITICAL` and fixable only.** HIGH findings are reported
  but do not fail the build. Tightening to HIGH would be reasonable once the
  base image's churn is understood; doing it now would likely mean routinely
  overriding the gate.
- **There is no automated check that new API routes are guarded.** Protection is
  opt-in per route by design (the reasoning is in `lib/api/guards.ts`), so a new
  route that forgets `requireUser` or `checkSameOrigin` is caught only in
  review. A lint rule or a test enumerating `app/api/**/route.ts` and asserting
  each handler calls a guard would close it.
- **The NodePort serves plain HTTP.** `NODE_ENV=production` marks the session
  cookie `Secure`, which browsers only send over HTTPS — this works at
  `localhost` because Chrome and Firefox treat it as a secure context, but on
  any other hostname the deployment needs TLS in front of it. That is an Ingress
  with a certificate, which needs an ingress controller installed in the
  cluster.
- **No RBAC is configured.** The `cloudsentinel.dev/db-client` label that gates
  database access is a *declaration*, not an authorisation: anyone able to create
  a pod in the namespace can attach it. That is inherent to NetworkPolicy
  selecting on labels, and restricting who may create pods is RBAC's job.
- **Images are built locally and never pushed.** `imagePullPolicy: Never` keeps
  the project free, but it means the cluster cannot pull them on a fresh node
  and `npm run k8s:build` has to be re-run after any code change. A registry is
  the real answer and is not free.
- **One Postgres replica, no replication and no backups.** The volume survives
  `k8s:down`, but nothing copies it anywhere. Losing the volume loses every
  `first_seen_at`.
- **The ML layer is not containerised.** `npm run ml:pipeline` still runs on the
  host, because a scikit-learn image is large and the pipeline is a batch job
  rather than a service. A CronJob running it in-cluster would be the natural
  next step, and `ml:save` already works from the `tools` image.
- **`npm run scan` is not run in the cluster either.** It needs LocalStack, which
  is deliberately not deployed here for the same reason it is absent from
  docker-compose.yml — it requires a personal auth token since the March 2026
  licensing change.
- **Anomaly triage is modelled nowhere yet.** Phase 5 gave findings a human
  overlay (`finding_triage`); anomalies have no equivalent, so there is no way
  to record "we looked, it was the quarterly export". The table shape would
  mirror `finding_triage`, but the semantics differ: an anomaly cannot be
  *resolved*, only *explained*, so the vocabulary should not be copied across
  unchanged.
- The detector windows activity by the hour. An attack deliberately spread thin
  — a few calls each, across days — stays under every per-hour threshold.
  Catching that needs sequence modelling rather than windowed aggregates, and is
  a different piece of work from anything in phase 6.
- Now that `volume_ratio` is measured against the same hour on other days, the
  tolerance inside a scheduled batch window is much wider than elsewhere. An
  attacker who knew the backup schedule could hide inside 02:00. Breaking the
  volume down by action and resource rather than counting calls would close it.
- Daylight saving is not modelled: principal working hours are a fixed UTC
  offset. A real deployment would see the off-hours feature go noisy twice a
  year for reasons that have nothing to do with security.
- `ml/requirements.txt` uses version floors rather than pins so the project still
  installs in a year. The cost is that a future scikit-learn could shift a
  marginal window across the alert budget boundary; the CI recall gate is set at
  0.6 against a current 0.8 to absorb that without hiding a real regression.
- The evaluation reports precision, but it is bounded well below 100% by
  construction — the alert budget is larger than the number of injected attacks,
  so a perfect detector still fills the remaining slots. Recall and the control
  false-positive count are the numbers that carry information, and the report
  says so.
- IAM group *policy documents* are resolved, but a group's own nested
  memberships are not — IAM does not nest groups, so this is complete in
  practice, noted only so it is not rediscovered as a gap.
- **Two security group rules are deliberately not implemented yet**:
  unrestricted *egress*, and the CIS check that the default VPC security group
  restrict all traffic. Both would fire on every security group in the current
  fixtures — including the compliant control — which would make the Phase 3
  contract test meaningless. They need a suppression/exception mechanism first.
  The reasoning is recorded in the header of `lib/rules/ec2.ts`.
- Rules flag only *unconditional* grants. A wildcard statement guarded by a
  `Condition` is not reported, because CloudSentinel does not evaluate condition
  operators and a stream of false positives on correctly-written conditional
  policies would destroy the tool's credibility. The trade-off is documented in
  `hasCondition` in `lib/rules/policy.ts`.
- Benchmark control ids (CIS v3.0.0, AWS FSBP) are recorded for orientation and
  should be re-verified against the current benchmark revision before this is
  ever pointed at a real account — CIS renumbers controls between versions.
- A reopened finding keeps its original `first_seen_at` and does not record how
  many times it has reopened. That is the honest reading of "first seen", but a
  `reopen_count` column would make repeat regressions visible on the dashboard.
- Triage state is modelled now (phase 5), but the two deferred security group
  rules still need a *rule-level* suppression mechanism, which is a different
  thing: triage hides one finding on one resource, whereas those rules need a
  way to exempt a whole class of resource before they can be switched on
  without breaking the phase 3 contract test.
- Sessions are stateless JWTs, so signing out only clears the browser
  cookie — a token already copied elsewhere keeps working until it expires
  (8 hours). `npm run user:revoke` is the immediate, everywhere version.
  Documented in `lib/auth/session.ts`.
- Login rate limiting is in-process, so it resets on restart and would not
  hold across more than one instance. Fine for a locally-run tool; a real
  deployment wants a shared store or a limit at the reverse proxy. The
  limitations are written out in `lib/api/rate-limit.ts`.
- A finding that is resolved and later reopens keeps whatever triage state it
  had. Arguably a reopened finding should return to `untriaged` so a fix that
  regressed gets looked at again rather than staying suppressed.
## Full 6-8 week phased plan
See `cloudsentinel-project-plan.md` (already generated) for the complete
week-by-week breakdown, resume bullet draft, and free-tools reference table.

