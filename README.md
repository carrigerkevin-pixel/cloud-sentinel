# CloudSentinel

A hybrid rule-based and ML-based **Cloud Security Posture Management (CSPM)** tool.
It audits a simulated AWS environment for misconfigurations, will detect anomalous
behaviour via a machine-learning layer, and presents findings in a dashboard.

Built as a portfolio project — Georgia Tech CS, Cybersecurity thread.

```
LocalStack ──▶ collectors ──▶ ResourceInventory ──▶ rule engine ──▶ Finding[] ──▶ dashboard
  (AWS API)    read-only        normalized model     12 CIS-style      ranked        (planned)
                                                        checks        + scored
```

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
| 6 — ML anomaly layer | planned |
| 7 — Docker + Kubernetes | planned |

**285 tests** on Node's built-in test runner — no test framework dependency, and no
Docker, LocalStack, or AWS credentials needed. A further **58 integration tests**
(`npm run test:db`) run against a real Postgres.

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
```

---

## The three CLIs

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
  collectors/             s3.ts, ec2.ts, iam.ts, inventory.ts — read-only AWS reads
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
db/migrations/            the schema, append-only
app/
  (app)/                  the authenticated dashboard: overview, findings, scans
  login/                  the only unauthenticated page
  components/             TriageControl, LogoutButton (client components)
  api/                    auth, findings, scans, summary, triage
scripts/
  seed-localstack.ts      npm run seed
  collect.ts              npm run collect
  scan.ts                 npm run scan
  db.ts                   npm run db:migrate / db:status
  user.ts                 npm run user:create / list / passwd / revoke / delete
docker-compose.yml        local Postgres
fixtures/inventory.json   committed snapshot, so everything above is testable offline
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

Four pages, all server-rendered:

| Page | Shows |
| --- | --- |
| `/` | Risk score, severity breakdown, what is hidden by triage, recent scans |
| `/findings` | Filterable list, most severe and longest-standing first |
| `/findings/<id>` | Evidence, remediation, every scan that reported it, triage |
| `/scans` | Scan history with new-finding counts and collection errors |

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
