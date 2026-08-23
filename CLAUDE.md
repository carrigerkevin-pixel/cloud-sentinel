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
 
## Environment notes specific to this machine
- OS: Windows, PowerShell as primary shell
- Python installed at `C:\Users\carri\AppData\Roaming\Python\Python314\`
  (user-level pip installs land in `...\Python314\Scripts` — this had to be
  added to PATH manually)
- PowerShell execution policy set to `RemoteSigned` for `CurrentUser` scope
  (needed for `npx` to run)
- AWS CLI dummy credentials configured (`test`/`test`/`us-east-1`) — LocalStack
  doesn't validate real credentials, just needs something present
## Not started yet (next steps)
1. Write LocalStack provisioning script to seed intentionally-insecure test
   resources: public S3 bucket, security group open on sensitive ports,
   over-permissive IAM user/policy without MFA
2. Build the Node/TS collector service to read those resources via AWS SDK
3. Build the rule engine (5-8 CIS-style checks)
4. Set up Postgres schema (resources, findings, scans tables) via Docker
5. Build the Next.js dashboard + API layer
6. Add the ML anomaly detection layer with synthetic CloudTrail logs
7. Containerize everything, deploy via local Kubernetes (`kind`/`minikube`)
8. Security hardening pass, README, demo video
## Full 6-8 week phased plan
See `cloudsentinel-project-plan.md` (already generated) for the complete
week-by-week breakdown, resume bullet draft, and free-tools reference table.

