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
Before writing any file, editing any file, or running any command, Claude gives
a short plain-language explanation of what it is about to do and why, then stops
and waits for explicit approval. One explanation per step — no batching several
files behind a single approval, and no writing first and explaining afterward.
Reading existing files to gather context does not require approval.

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
   new-geo logins)
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
 
## Environment notes specific to this machine
- OS: Windows, PowerShell as primary shell
- Python installed at `C:\Users\carri\AppData\Roaming\Python\Python314\`
  (user-level pip installs land in `...\Python314\Scripts` — this had to be
  added to PATH manually)
- PowerShell execution policy set to `RemoteSigned` for `CurrentUser` scope
  (needed for `npx` to run)
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
1. **Phase 5 — Next.js dashboard + API.** Findings list, risk score, scan
   history, triage UI, JWT auth. `lib/db/scans.ts` already exposes
   `recentScans()` and `openFindings()` (with occurrence counts and lifecycle
   dates), so the API layer has queries to build on.
2. Add the ML anomaly detection layer with synthetic CloudTrail logs
3. Containerize everything, deploy via local Kubernetes (`kind`/`minikube`)
4. Security hardening pass, README, demo video

Known follow-ups, none blocking:
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
- Triage state (acknowledged, suppressed, false positive) is not modelled yet.
  It belongs with the rule-suppression mechanism the two deferred security group
  rules also need, and both want a database — which now exists.
## Full 6-8 week phased plan
See `cloudsentinel-project-plan.md` (already generated) for the complete
week-by-week breakdown, resume bullet draft, and free-tools reference table.

