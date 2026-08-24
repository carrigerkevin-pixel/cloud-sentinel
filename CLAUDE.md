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
## Not started yet (next steps)
1. **Phase 3 — rule engine.** 5-8 CIS-style checks reading a
   `ResourceInventory`. Target the 13 findings in `EXPECTED_FINDINGS` in
   `scripts/seed-localstack.ts`; the compliant controls must produce zero
   findings. Rules must consult a resource's `unobserved` list before drawing
   any conclusion from a `null` config field — a failed observation is not a
   clean result. Can be built entirely against `fixtures/inventory.json` with
   no LocalStack running.
2. Set up Postgres schema (resources, findings, scans tables) via Docker
3. Build the Next.js dashboard + API layer
4. Add the ML anomaly detection layer with synthetic CloudTrail logs
5. Containerize everything, deploy via local Kubernetes (`kind`/`minikube`)
6. Security hardening pass, README, demo video

Known follow-ups, none blocking:
- IAM group *policy documents* are resolved, but a group's own nested
  memberships are not — IAM does not nest groups, so this is complete in
  practice, noted only so it is not rediscovered as a gap.
- No GitHub Actions workflow yet. `npm test` needs no services, so CI is a
  short next step whenever it is wanted.
## Full 6-8 week phased plan
See `cloudsentinel-project-plan.md` (already generated) for the complete
week-by-week breakdown, resume bullet draft, and free-tools reference table.

