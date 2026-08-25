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
| 4 — Postgres schema | planned |
| 5 — Next.js dashboard + API | planned |
| 6 — ML anomaly layer | planned |
| 7 — Docker + Kubernetes | planned |

**207 tests**, run on Node's built-in test runner. No test framework dependency, and
no Docker, LocalStack, or AWS credentials are needed to run them.

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
environment produces identical ids, which is what will let the dashboard track a
finding's lifecycle instead of inventing a fresh set of problems on every run.

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
  util/concurrency.ts     bounded parallelism
scripts/
  seed-localstack.ts      npm run seed
  collect.ts              npm run collect
  scan.ts                 npm run scan
fixtures/inventory.json   committed snapshot, so everything above is testable offline
```

---

## Tech stack

TypeScript · Node.js · Next.js · PostgreSQL · Docker · Kubernetes · Python + scikit-learn
· LocalStack · GitHub Actions

## Dashboard

The Next.js dashboard is not built yet (phase 5). `npm run dev` currently serves the
default scaffold on [http://localhost:3000](http://localhost:3000).
