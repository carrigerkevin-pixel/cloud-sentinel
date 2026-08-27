# Security policy

CloudSentinel is a security tool, so it is fair to hold it to the standard it
applies to everything it scans. This document says what the project defends
against, what it deliberately does not, and how to report something that is
wrong.

## Reporting a vulnerability

Please use **[GitHub's private vulnerability reporting](https://github.com/carrigerkevin-pixel/cloud-sentinel/security/advisories/new)**
rather than opening a public issue, so a problem can be fixed before it is
described in public.

Useful things to include: what an attacker can do, the smallest set of steps
that shows it, and which file you think is responsible. A proof of concept is
welcome but not required.

This is a personal portfolio project rather than a funded product. There is no
bounty and no guaranteed response time, but reports will be read and taken
seriously.

## Scope

**What this project is.** A cloud security posture tool that audits a
*simulated* AWS environment provided by [LocalStack](https://localstack.cloud),
scores the misconfigurations it finds, detects behavioural anomalies in a
*synthetic* activity log, and presents all of it in a dashboard.

**What it is not.** It has never been pointed at a real AWS account. Every
address in the generated activity log comes from the RFC 5737 documentation
ranges and the account id is AWS's `123456789012` placeholder — a public
repository must not appear to accuse a real IP address of credential theft.

### In scope

- Authentication and session handling (`lib/auth/`)
- The API routes and their guards (`app/api/`, `lib/api/`)
- SQL construction and the database client (`lib/db/`)
- Anything that reads untrusted input: the collectors, the policy analyser, and
  the anomaly ingest boundary
- The container images and Kubernetes manifests (`Dockerfile`, `k8s/`)

### Out of scope

- **The intentionally insecure fixtures.** `scripts/seed-localstack.ts` creates a
  public S3 bucket, a security group open to the world on SSH and RDP, and an
  over-privileged IAM user *on purpose*. They exist so the rule engine has
  something to find, they live only in LocalStack, and they are the point rather
  than a bug.
- **Anything requiring an attacker to already have code execution on the
  machine.** The database and LocalStack are bound to loopback, and the project
  assumes the local machine is trusted.
- **Findings in dependencies with no path from this code.** `npm audit` runs in
  CI; a report that a transitive package has a vulnerability in a function
  nothing here calls is useful information rather than a vulnerability in this
  project.

## Threat model

The dashboard's data is unusually sensitive for its size. A findings list is a
ranked, current inventory of exactly where an environment is weakest — which
bucket is public, which port is open to the internet, which user has no MFA.
That shapes most of the decisions below: the primary asset being protected is
not the application but *the report it produces*.

| Adversary | Assumed capability | Primary defence |
| --- | --- | --- |
| Unauthenticated network attacker | Can reach the dashboard's port | Every route guarded; no sign-up exists; login is rate limited |
| Attacker with a stolen session token | Holds a valid cookie | `token_version` revocation; `npm run user:revoke` invalidates immediately |
| Hostile website | Can make a victim's browser send requests | `SameSite=strict` cookie, plus a server-side `Origin` check |
| Script injected into a page | Can run JavaScript in the origin | Nonce-based CSP; `httpOnly` cookie is unreadable to script |
| Compromised dashboard process | Arbitrary code in the container | No AWS SDK, no `scripts/`, read-only filesystem, egress restricted to DNS and the database |
| Someone on the network path | Can observe or intercept traffic | Certificate-verified TLS to the database, with no way to disable verification |

### What each defence actually is

**Authentication.** Passwords are hashed with scrypt (N=16384) and a per-user
salt, with the cost parameters stored inside the hash so they can be raised
later without locking anyone out. There is no sign-up page: accounts exist only
via `npm run user:create`, which prompts with echo suppressed rather than taking
the password as an argument that would land in shell history and the process
list. Login verifies against a decoy hash when no account matches, so an unknown
email costs the same time as a known one and the form cannot be used to
enumerate accounts.

**Sessions.** HS256 JWTs implemented directly on `node:crypto`. The algorithm is
decided by the code and never read from the token, so `alg: none` and
algorithm-confusion forgeries are rejected, and the signature is verified before
any claim is trusted. The token rides in an `httpOnly`, `SameSite=strict` cookie
— not `localStorage`, which an injected script can read and exfiltrate. Because
a JWT cannot normally be recalled before it expires, every token embeds a
`token_version` that is compared against the database on each request; changing
a password or a role bumps it, so a demoted admin loses access on their next
request rather than whenever their token happens to expire.

**Injection.** Every query is parameterised, with values sent separately from
the SQL text. This matters more than it might appear: resource names and ARNs
come from an environment CloudSentinel does not control, and are exactly the
kind of attacker-influenced string that makes concatenated SQL dangerous.
Finding ids contain slashes and are base64url-encoded for URLs, with decoding
validated including a rejection of control characters.

**Secrets.** Nothing is committed. `.env` is gitignored and `.env.example`
carries names without values. `lib/auth/jwt.ts` refuses to start without a
signing secret of at least 32 characters rather than falling back to a default
that every reader of this repository would know. The database client never puts
a credential in output or an error message. In Kubernetes, secrets are generated
at deploy time and piped to `kubectl` over stdin rather than passed as
command-line arguments.

**The scanner's own honesty.** A verdict has three states — `pass`, `fail`, and
`inconclusive` — and inconclusive is never rounded down to a pass. Every rule
checks whether a setting was actually readable before concluding anything from a
missing value, so a failed observation can never be reported as a clean result.
Suppressing a finding hides it from the default view and changes nothing about
whether the bucket is still public; the overview always reports the true total
alongside the filtered one, because a risk score that improved when you clicked
"suppress" would reward hiding problems instead of fixing them.

## Known limitations

These are documented rather than hidden, in the files where they apply. A
control believed to be present and in fact absent is worse than a known gap.

- **The Kubernetes NodePort serves plain HTTP.** Session cookies are marked
  `Secure` in production, which works at `localhost` because browsers treat it
  as a secure context, but any other hostname needs TLS in front of it.
- **Login rate limiting is in-process.** It resets on restart and, with two
  dashboard replicas, its effective limit is doubled because each pod counts
  attempts separately. A real deployment needs a shared store or a limit at the
  proxy. See `lib/api/rate-limit.ts`.
- **Signing out only clears the browser cookie.** A token already copied
  elsewhere keeps working until it expires, up to 8 hours. `npm run user:revoke`
  is the immediate, everywhere version.
- **The rate limiter trusts `x-forwarded-for`**, and the `Origin` check trusts
  `Host`. Both are only as trustworthy as the proxy in front of them.
- **No RBAC in the Kubernetes deployment.** The `cloudsentinel.dev/db-client`
  label that gates database access is a declaration, not an authorisation:
  anyone able to create a pod in the namespace can attach it.
- **`style-src` allows `'unsafe-inline'`.** Next injects unnonced inline styles
  for critical CSS and fonts. The exposure is CSS injection, which is real but
  well short of script execution; `script-src` allows no inline script without a
  per-response nonce.
- **The rule engine does not evaluate IAM conditions.** A wildcard statement
  guarded by a `Condition` is reported as inconclusive rather than as a
  violation, because CloudSentinel cannot evaluate condition operators and a
  stream of false positives on correctly-written policies would destroy the
  tool's credibility. See `hasCondition` in `lib/rules/policy.ts`.
- **The ML figures come from synthetic data** generated by this project's own
  rules, so the models are partly tested against the generator's assumptions.
  They demonstrate the pipeline works; they are not a claim about accuracy on a
  real AWS account. `ml/evaluate.py` prints this caveat itself.

## Verification

Security properties are asserted in CI on every push, not just described here:

- **388 unit tests**, roughly two thirds of the JWT suite being forgery
  attempts, plus the cross-site request checks and the TLS decision logic.
- **Integration tests** against a real PostgreSQL.
- **A real Kubernetes deployment**, which then proves the NetworkPolicy is
  *enforced* rather than merely stored — a probe pod without the `db-client`
  label must fail to reach the database — and that the dashboard's database
  connections are TLS-encrypted, read back from `pg_stat_ssl`.
- **Container image scanning** for known vulnerabilities with a fix available.
