# CloudSentinel

A hybrid rule-based and ML-based **Cloud Security Posture Management (CSPM)** tool.
It audits a simulated AWS environment for misconfigurations, detects anomalous
behaviour via a machine-learning layer, and presents both in a dashboard.

Built as a portfolio project — Georgia Tech CS, Cybersecurity thread.

Two independent pipelines, answering two different questions:

```
  "what is configured wrongly?"                        rule-based

    LocalStack ──▶ collectors ──▶ rule engine ──▶ Finding[]  ──┐
     (AWS API)     read-only      12 CIS-style     ranked      │
                                     checks       + scored     │
                                                               ├─▶ Postgres ──▶ dashboard
  "who is behaving strangely?"                    ML-based     │
                                                               │
    activity log ──▶ features ──▶ 2 detectors ──▶ Anomaly[]  ──┘
    (CloudTrail)     14, per       forest +        scored
                  principal-hour   stats control  + explained
```

The second pipeline exists because the first one cannot see everything. A rule
engine reads *configuration*, and an intruder using stolen but legitimate
credentials changes none — every call they make is one they are authorised to
make. What gives them away is the pattern: the wrong hour, an unfamiliar
address, a sequence that principal has never performed.

---

## Status

| Phase | State |
| --- | --- |
| 1 — LocalStack fixtures | ✅ complete |
| 2 — Collector service | ✅ complete |
| 3 — Rule engine | ✅ complete |
| CI (GitHub Actions) | ✅ complete |
| 4 — Postgres persistence | ✅ complete |
| 5 — Next.js dashboard + API | ✅ complete |
| 6 — ML anomaly layer | ✅ complete |
| 7 — Docker + Kubernetes | planned |

**369 tests** on Node's built-in test runner — no test framework dependency, and no
Docker, LocalStack, Python, or AWS credentials needed. A further **76 integration
tests** (`npm run test:db`) run against a real Postgres.

---

## Quick start

Requires Node 24+ (the CLIs import `.ts` files directly, relying on Node's built-in
type stripping) and, for live scanning, LocalStack on `http://localhost:4566`.

```bash
npm install

# Scan the committed inventory snapshot — no Docker, no LocalStack, no credentials
npm run scan:fixture

# Full loop against a live LocalStack container
npm run seed        # provision the fixtures
npm run collect     # read the environment
npm run scan        # evaluate the rules

# Store scan history, so findings gain first-seen dates and lifecycle
cp .env.example .env      # then set POSTGRES_PASSWORD — see that file
docker compose up -d db
npm run db:migrate
npm run scan -- --save

# Behavioural anomaly detection (needs Python 3.11+; touches no network at all)
npm run ml:setup      # one-off: creates ml/.venv, installs numpy + scikit-learn
npm run ml:pipeline   # generate a synthetic activity log, detect, evaluate
npm run ml:save       # store the run so the dashboard can show it
```

---

## The CLIs

### `npm run seed` — fixtures

Provisions an intentionally-misconfigured AWS account in LocalStack, plus a compliant
control group the rule engine must leave alone. Idempotent; `npm run seed:down` removes
everything it created.

| Fixture | Posture |
| --- | --- |
| `cloudsentinel-public-assets` (S3) | Block Public Access off, public-read policy + ACL, no versioning, no logging |
| `cloudsentinel-open-mgmt` (SG) | tcp/22 and tcp/3389 open to `0.0.0.0/0`, tcp/22 open to `::/0` |
| `cloudsentinel-admin-svc` (IAM) | `*:*` managed policy, unrestricted `iam:PassRole`, console access with no MFA |
| `cloudsentinel-group-member` (IAM) | Administrator **only** through group membership — invisible from the user object |
| `cloudsentinel-private-logs` (S3) | Control — PAB on, versioning on, logging on, encrypted |
| `cloudsentinel-restricted-app` (SG) | Control — tcp/443 from `10.0.0.0/16` only |
| `cloudsentinel-readonly-svc` (IAM) | Control — least privilege, no console, no access keys |

> **Safety.** These fixtures are deliberately vulnerable. `lib/aws/localstack.ts` hard-fails
> on any endpoint that is not loopback and pins credentials to LocalStack dummies, so the
> seeder cannot reach a real AWS account even if the ambient AWS profile points at one.

### `npm run collect` — collector

Reads S3 buckets, EC2 security groups, and IAM users through the AWS SDK and normalizes
them into a single `ResourceInventory`. **Strictly read-only** — every command it issues
is a `List*`, `Get*`, or `Describe*`.

```bash
npm run collect                                   # human-readable summary
npm run collect -- --json                         # raw inventory JSON
npm run collect -- --out fixtures/inventory.json  # regenerate the committed snapshot
```

### `npm run scan` — rule engine

Runs all 12 rules over an inventory and reports findings ranked by severity.

```bash
npm run scan                                        # collect live, then evaluate
npm run scan -- --input fixtures/inventory.json     # evaluate a saved inventory
npm run scan -- --severity high                     # display only high and critical
npm run scan -- --fail-on critical                  # exit 1 on any critical — a CI gate
npm run scan -- --rules                             # list the registered rules
npm run scan -- --json --out findings.json          # machine-readable output
```

Exit status: `0` clean, `1` threshold tripped or the inventory had collection errors,
`2` bad arguments.

### `npm run db:migrate` — scan history

Postgres stores scan history and finding lifecycle. `--save` on a scan writes it and
updates what is new, still open, reopened, or resolved.

```bash
docker compose up -d db     # Postgres 17, bound to 127.0.0.1 only
npm run db:migrate          # apply the schema
npm run db:status           # what is applied, pending, or modified
npm run scan -- --save      # store a scan
npm run test:db             # integration tests (creates its own database)
```

The database has **no default password**: Compose refuses to start until
`POSTGRES_PASSWORD` is set in `.env`. That file is gitignored; `.env.example` is
committed and carries no values.

### `npm run logs:gen` / `npm run ml:*` — the anomaly layer

Generates synthetic activity, scores it with both detectors, and stores the run.
Nothing here touches AWS, LocalStack, or the network.

```bash
npm run logs:gen                          # 30 days, ~36,500 events, 5 labelled attacks
npm run logs:gen -- --days 7 --seed demo  # a shorter, differently-seeded dataset
npm run logs:gen -- --no-attacks          # clean traffic, to measure false positives

npm run ml:setup                          # one-off: ml/.venv + numpy + scikit-learn
npm run ml:features                       # inspect the feature matrix, no model
npm run ml:detect                          # run both models → fixtures/anomalies.json
npm run ml:detect -- --contamination 0.005 # a tighter alert budget
npm run ml:evaluate                       # score both against the answer key
npm run ml:pipeline                       # generate → detect → evaluate

npm run ml:save                           # store a run in Postgres
npm run ml:save -- --dry-run              # validate the detections file only
npm run ml:runs                           # list stored runs
```

The generated log is **not committed**. Unlike `fixtures/inventory.json`, which needs
LocalStack to reproduce, this is pure deterministic computation — same seed, byte-identical
output, 190ms — so committing 27MB that any checkout can rebuild would bloat every clone.
CI regenerates it.

---

## Rule catalogue

| Rule | Severity | Benchmark |
| --- | --- | --- |
| `s3-block-public-access` | critical | CIS AWS Foundations v3.0.0 2.1.4 |
| `s3-public-bucket-policy` | critical | AWS FSBP S3.2 |
| `s3-public-bucket-acl` | critical | AWS FSBP S3.2 |
| `s3-versioning-disabled` | medium | AWS FSBP S3.14 |
| `s3-access-logging-disabled` | medium | AWS FSBP S3.9 |
| `s3-default-encryption-disabled` | low | AWS FSBP S3.4 |
| `ec2-unrestricted-ingress` | critical / high | CIS AWS Foundations v3.0.0 5.2 / 5.3 |
| `iam-admin-policy-direct` | critical | CIS AWS Foundations v3.0.0 1.16 |
| `iam-admin-policy-via-group` | critical | CIS AWS Foundations v3.0.0 1.16 |
| `iam-unrestricted-passrole` | high | privilege-escalation check |
| `iam-console-without-mfa` | high | CIS AWS Foundations v3.0.0 1.10 |
| `iam-long-lived-access-key` | high | CIS AWS Foundations v3.0.0 1.11 / 1.14 |

Control identifiers are recorded for orientation and should be re-verified against the
current benchmark revision before this is pointed at a real account — CIS renumbers
controls between major versions.

---

## The ML anomaly layer

Unsupervised behavioural detection over CloudTrail-style activity logs: one row per
principal per hour, fourteen features, two models.

### The data

There is no public dataset of labelled AWS control-plane intrusions, and there should
not be — a real trail records who did what from where, and no organisation publishes
one. So the activity is synthesised (`npm run logs:gen`): six principals over 30 days,
~36,500 events, with **five labelled attacks** hidden in it.

Synthetic data costs something real — a model evaluated on it is partly tested against
the generator's own assumptions — and buys something the alternative cannot offer:
**ground truth**. Without it, "the model flagged four things" is unfalsifiable.

Two of the six principals are **controls**, and they are the point of the exercise:

| Principal | Why it is hard |
| --- | --- |
| `cloudsentinel-backup-service` | Runs 24/7, ~600 calls a night at 02:00. Any detector keyed on "night-time" or "high volume" reports it every single day. |
| `dave-admin` | `AttachUserPolicy` and `CreateAccessKey` are his job. Any detector keyed on "sensitive IAM action" reports him constantly. |

Both must come out clean. That is the whole argument for baselining **per principal**:
the same API call is unremarkable from Dave and alarming from an analyst who has never
touched IAM. A model that cannot express that either misses the real escalation or
drowns the account in noise — and both failures end with the tool switched off.

The generator writes events and labels to **separate files**, and the detector never
opens the label file. Only `ml/evaluate.py` does, after detection has finished. For an
unsupervised model that is not a nicety: a model that could see the labels would learn
to predict them, and the resulting accuracy would measure nothing.

### Does the machine learning earn its place?

It is easy to add scikit-learn, report a good number, and imply the model is
responsible when a handful of `if` statements would have done the same. So the pipeline
runs an **Isolation Forest** and a **dependency-free statistical control** (per-principal
robust z-scores) over identical features, gives them **the same alert budget**, and
reports both. Equal budget matters: the interesting question is not "which model alerts
more" but *given a fixed amount of human attention, which spends it better?*

30 days, 1,990 windows, 20 alerts per model:

| | recall | control false positives | most repeated alert |
| --- | --- | --- | --- |
| Isolation Forest | 80% (4/5) | 10 | `dave-admin` ×7 (35%) |
| Statistical baseline | 80% (4/5) | 13 | **`backup-service` ×12 (60%)** |

Both find four of five. **The ML does not win on recall — it wins by repeating itself
less.** The statistical model spends twelve of its twenty alerts re-reporting the same
nightly cron job, because a per-feature threshold has no notion of recurrence. The
forest spends three: thirty near-identical batch windows form a dense cluster, and a
point in a dense cluster is not *isolated*. That is the difference between a tool
somebody keeps reading and one they mute in week two — and a muted detector's real
recall is zero, whatever its recall column says.

The fifth scenario (`off_hours_access`) is missed by both, **by design**. Ordinary work,
usual address, usual region — only the clock is wrong. It is the deliberately weak
signal, included to test whether one weak feature is enough. It is not, and the
evaluation reports that rather than tuning until it disappears.

> ⚠️ These figures come from synthetic data generated by this project's own rules. They
> demonstrate the pipeline works end to end. They are **not** a claim about accuracy on
> a real AWS account. `ml/evaluate.py` prints this caveat itself, so the number cannot
> travel without it.

### Three things that took a second attempt

Each was found by watching the first version fail, and each is documented where it
lives rather than only here.

**Volume had to be measured against the hour of day.** The first `volume_ratio` divided
by the principal's overall median hourly volume — so the backup role's 02:00 batch, at
six times its own average, scored ~6 every night for a month and out-ranked two real
attacks. Comparing an hour against *the same hour on other days* removed the entire
class of false positive.

**Rates over small windows are noise.** A four-call hour with one permission error has a
25% error rate, which against a 1% background looks catastrophic and is one stale
script. Every rate is now shrunk toward the principal's own prior
(`(observed + k·prior) / (n + k)`, k = 10): thin evidence barely moves the estimate,
while a 31-call enumeration burst still reads as 0.64. This alone took the forest from
60% to 80% recall.

**A single worst feature cannot rank anything.** Several features are near-binary —
`hour_rarity` is ~0 in-hours and ~1 out-of-hours — so scoring by the max produced ties
across every off-hours window, and array order decided which ones got reported. The
baseline now sums its three worst features, each capped at 25σ so one near-constant
column cannot dominate.

### Explaining a model that cannot explain itself

An Isolation Forest score is an average path length across random trees. There is no
honest way to attribute it to a single feature, and an alert reading *"principal X,
03:00, score 99.9"* gives an analyst nowhere to start — after a few of those they stop
reading alerts.

So the forest decides **what** to flag and the statistical model explains **why** it is
unusual: every detection carries the three most extreme features in plain language
("call volume was 22× this principal's normal hour, against 322 distinct objects"). The
dashboard states that this is supporting evidence rather than the forest's internal
reasoning, because the alternative is a nicer story that is not true.

### Anomalies are not findings

They are stored in separate tables and behave differently on purpose. A finding is a
*condition that persists* — a bucket stays public until someone fixes it — so `findings`
carries `first_seen_at`, `last_seen_at` and an open/resolved status.

An anomaly is an observation about **one specific past hour**. It cannot be fixed, and it
cannot recur: a later strange hour is a different hour. So an anomaly row is immutable
and has no status. Giving it a lifecycle would have looked consistent and been wrong.

---

## Design decisions

**A verdict has three states, not two.** The collectors record an `unobserved` list
naming every setting they could not read. A `null` config field is ambiguous on its own:
it can mean "AWS says this is not configured" — frequently the finding itself — or "the
call to find out failed", which is no information at all. Rules check that list before
concluding anything, and answer `inconclusive` rather than `pass` when the data is
missing. A security scanner's worst failure mode is a false negative, because nothing
about a green result invites a second look.

**Group-inherited permissions are resolved.** A user with no attached policies, no inline
policies, no access keys, and no console password can still be a full account
administrator through one group membership. Every user-level field says "harmless". The
`cloudsentinel-group-member` fixture exists to prove the engine catches it, and it is
reported under its own rule id because fixing a group is a different and riskier
operation than fixing one user.

**Findings have deterministic ids.** `<ruleId>|<resourceId>|<key>`, where the key is
derived from configuration rather than array position. Re-scanning an unchanged
environment produces identical ids, which is what lets the database track a finding's
lifecycle instead of inventing a fresh set of problems on every run.

**Absence is never treated as proof of a fix.** The tempting implementation of
lifecycle is "any stored finding missing from this scan is resolved". That is wrong in
the dangerous direction — it silently closes real problems and reports success for work
nobody did. A finding is resolved only if the scan had no collection errors *and*
either the resource is gone (`resource_removed`) or the resource was inspected and the
rule stayed quiet (`fixed`). Anything else stays open and is reported as "could not be
re-checked". A scan that fails halfway resolves nothing at all.

**False positives are treated as a real cost.** Public web ports open to `0.0.0.0/0` are
not flagged — that is the intended configuration for most internet-facing fleets.
Traffic scoped to a peer security group is not flagged; that is the correct pattern.
Wildcard policy statements guarded by a `Condition` are not flagged, because
CloudSentinel does not evaluate condition operators and a stream of alerts on
correctly-written conditional policies would teach its reader to ignore the tool. Each
trade-off is documented at the code that makes it.

**The engine cannot be taken down by one bad rule.** A rule that throws is caught and
converted into an inconclusive finding, so one unexpected config shape degrades coverage
instead of destroying the scan — and the gap is still reported.

---

## Layout

```
lib/
  aws/localstack.ts       client construction; refuses non-loopback endpoints
  types/resource.ts       the normalized resource model (types only)
  types/cloudtrail.ts     activity-log + ground-truth label model (types only)
  types/anomaly.ts        what the Python layer returns (types only)
  collectors/             s3.ts, ec2.ts, iam.ts, inventory.ts — read-only AWS reads
  logs/generator.ts       synthetic CloudTrail, 5 labelled attacks, 2 controls
  anomalies/ingest.ts     validates the detections file at the language boundary
  rules/
    types.ts              rule/finding vocabulary, severity weights
    policy.ts             shared IAM/S3 policy analysis
    s3.ts ec2.ts iam.ts   the 12 rules
    engine.ts             the runner, finding ids, risk score
  db/
    client.ts             pooled connections, loopback-only by default
    migrate.ts            numbered, checksummed migrations
    lifecycle.ts          finding lifecycle rules (pure, no SQL)
    scans.ts              persistence and history queries
    users.ts              accounts, login, session revocation
    triage.ts             triage state + append-only audit trail
    dashboard.ts          every read query the dashboard makes
    anomalies.ts          detection runs and their alerts
  auth/
    password.ts           scrypt hashing, decoy hash, rehash-on-login
    jwt.ts                HS256 on node:crypto; rejects alg:none
    session.ts            httpOnly SameSite=strict cookie, per-request checks
  api/
    http.ts               JSON helpers, requireUser / requireAdmin guards
    rate-limit.ts         login throttling
    finding-id.ts         base64url ids for URLs (real ids contain slashes)
  ui/format.ts            severity colours, dates, triage labels
  util/concurrency.ts     bounded parallelism
  util/env.ts             .env loading
  util/random.ts          seeded PRNG — synthetic data only, never for secrets
ml/
  requirements.txt        numpy, scikit-learn (installed into a local venv)
  features.py             14 behavioural features, leave-one-window-out profiling
  baseline.py             robust z-score control — no ML, no dependencies
  detect.py               Isolation Forest, shared alert budget, evidence
  evaluate.py             the ONLY module permitted to read the labels
db/migrations/            the schema, append-only
app/
  (app)/                  the dashboard: overview, findings, anomalies, scans
  login/                  the only unauthenticated page
  components/             TriageControl, LogoutButton (client components)
  api/                    auth, findings, scans, summary, triage
scripts/
  seed-localstack.ts      npm run seed
  collect.ts              npm run collect
  scan.ts                 npm run scan
  db.ts                   npm run db:migrate / db:status
  user.ts                 npm run user:create / list / passwd / revoke / delete
  gen-logs.ts             npm run logs:gen
  ml.ts                   npm run ml:setup / features / detect / evaluate
  anomalies.ts            npm run ml:save / ml:runs
docker-compose.yml        local Postgres
fixtures/inventory.json   committed snapshot, so everything above is testable offline
fixtures/cloudtrail.json  NOT committed — deterministic, rebuilt by npm run logs:gen
```

---

## Tech stack

TypeScript · Node.js · Next.js · PostgreSQL · Docker · Kubernetes · Python + scikit-learn
· LocalStack · GitHub Actions

## Dashboard

```bash
docker compose up -d db
npm run db:migrate
npm run user:create -- you@example.com --admin   # prompts for a password
npm run scan -- --save                           # needs LocalStack; see quick start
npm run dev                                      # http://localhost:3000
```

`CLOUDSENTINEL_JWT_SECRET` must be set in `.env` — see `.env.example`. There is no
default value anywhere in the code, and the app refuses to start without one.

Six pages, all server-rendered:

| Page | Shows |
| --- | --- |
| `/` | Risk score, severity breakdown, what is hidden by triage, recent scans |
| `/findings` | Filterable list, most severe and longest-standing first |
| `/findings/<id>` | Evidence, remediation, every scan that reported it, triage |
| `/anomalies` | Flagged principal-hours, both models' scores, where alerts landed |
| `/anomalies/<id>` | All 14 features, the evidence, the events involved |
| `/scans` | Scan history with new-finding counts and collection errors |

The anomalies pages always show **both** models' scores side by side rather than a
single verdict, because the disagreement is the informative part — a window both
models flagged is a stronger signal than one only the forest isolated. `/anomalies`
also shows how the alerts are distributed across principals: a run where one
principal accounts for most of them is a run whose reader will start skipping it,
and that is the failure mode that quietly turns a detector's real recall to zero.

### Authentication

There is no sign-up page. Accounts are created only from the command line, because a
security dashboard that lets anonymous visitors register themselves is not one worth
running.

- **Passwords** are hashed with scrypt (N=16384) and a per-user salt. The cost
  parameters are stored inside the hash string, so they can be raised later without
  invalidating existing passwords — an old hash still verifies, and is upgraded on the
  next successful login.
- **Login does not leak which emails exist.** A wrong password and an unknown address
  produce the same response *and* take the same time: when no account matches, the
  password is still verified against a decoy hash. An identical message delivered a
  hundred times faster leaks the same fact.
- **Sessions are JWTs**, HS256, signed and verified with `node:crypto` rather than a
  library. The algorithm is fixed in code and never read from the token, so the
  `alg: none` and algorithm-confusion forgeries are rejected. The signature is checked
  before any claim is trusted.
- **The token lives in an `httpOnly`, `SameSite=strict` cookie**, not `localStorage`.
  A cross-site scripting flaw can read `localStorage` and carry a session off the
  machine; it cannot read an httpOnly cookie. `SameSite=strict` is what stops another
  site from making authenticated requests with it.
- **Sessions can be revoked**, which a JWT normally cannot be. Each token carries the
  `token_version` it was issued under, compared against the database on every request.
  `npm run user:revoke` bumps it and every token for that account stops working
  immediately. Changing a password or a role bumps it too, so a demoted admin loses
  admin access on their next request rather than whenever their token expires.
- **Login is rate limited** — 10 attempts per 15 minutes per client, checked before
  any hashing happens. Each scrypt verification costs the server ~100 ms, so an
  unthrottled login endpoint is a denial-of-service amplifier as well as a guessing
  target.

### Triage, and why it cannot flatter the numbers

Findings can be marked **acknowledged**, **suppressed**, or a **false positive**.
Two rules make this trustworthy rather than a way to make problems go away:

**Triage never changes whether a finding is open.** `findings.status` is the
scanner's claim about reality and only the lifecycle logic sets it. Triage is the
human overlay, in its own table. A suppressed finding on a still-public bucket reads
as *open* and *suppressed* at the same time, because that is the truth. If clicking
"suppress" marked something resolved, every report the tool produced would be
worthless.

**Nothing disappears silently.** The overview shows the filtered count, the true
total, and how many findings are hidden. The risk score is computed from every open
finding. A score that dropped when you suppressed something would reward hiding
problems instead of fixing them.

Every change is appended to `triage_events` with the actor's email stored as text —
so deleting a user account cannot erase who suppressed what — and a written
justification is required for any state that hides a finding, enforced both in the
application and by a database CHECK constraint. Viewers can read every decision and
its author; only admins can make one.
