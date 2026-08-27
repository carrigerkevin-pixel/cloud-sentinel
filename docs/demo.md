# CloudSentinel — demo walkthrough

A shot-by-shot script for the project demo recording. Roughly **six minutes**,
which is about the limit of what a reviewer will watch.

It is written to be read aloud while the commands run. Every command here has
been run end to end; nothing in it is aspirational.

## Why this script exists

The temptation with a project this size is to show everything. That produces a
tour of features, which is forgettable. The structure below instead shows **four
decisions and their consequences**, because what an interviewer is assessing is
judgement rather than surface area:

1. The tool refuses to guess (`inconclusive` is a first-class verdict).
2. The ML has to justify its place against a control that has no ML in it.
3. Hiding a problem never improves the score.
4. The security controls are proven, not asserted.

Anything that does not serve one of those is cut.

---

## Before recording

```bash
# 1. Infrastructure
docker compose up -d db                # Postgres
# start LocalStack, then:
npm run seed                           # the intentionally-insecure fixtures

# 2. Schema and an account
npm run db:migrate
npm run user:create -- demo@example.com --admin

# 3. Data to look at
npm run scan -- --save                 # findings, with first-seen dates
npm run ml:setup && npm run ml:pipeline
npm run ml:save

# 4. The cluster, if the Kubernetes section is included
npm run k8s:cluster && npm run k8s:build && npm run k8s:up
npm run k8s:user -- demo@example.com --admin
```

Checklist for the recording itself:

- **Terminal font large enough to read on a phone.** Most of this will be
  watched at half size in a browser tab.
- **Close every other tab.** A notification popping up mid-recording is the
  single most common reason a take is wasted.
- `clear` between sections so each one starts clean.
- **Do not show `.env`, `k8s/tls/`, or the output of `kubectl get secret -o
  yaml`.** They hold the real signing key and database password for the machine
  being recorded. This is worth stating explicitly because a demo of a security
  tool leaking its own credentials is the kind of detail that gets noticed.

---

## 0:00 — What it is (30s)

> "CloudSentinel is a cloud security posture tool. It answers two different
> questions about an AWS environment: *what is configured wrongly*, using a rule
> engine, and *who is behaving strangely*, using an ML layer on activity logs.
>
> The second exists because the first cannot see everything. A rule engine reads
> configuration — and an intruder using stolen but valid credentials changes no
> configuration at all. Every call they make is one they're authorised to make."

Show the architecture diagram at the top of the README.

---

## 0:30 — The scanner (75s)

```bash
npm run scan:fixture
```

> "Thirteen findings across a public bucket, a security group open to the world
> on SSH and RDP, and an over-privileged IAM user. Risk score 87."

Point at a `PASS` line on one of the compliant control resources:

> "These three resources are deliberately clean. They're a false-positive
> baseline — if a rule ever starts firing on them, the rule is wrong, and a test
> asserts that."

Now the decision worth showing:

> "A verdict here has **three** states, not two: pass, fail, and *inconclusive*.
> If the collector couldn't read a setting, the rule says so instead of assuming
> it's fine. Every rule checks that before it concludes anything.
>
> That matters because the failure mode of a scanner is silent. A tool that
> reports a clean result for something it couldn't actually read is worse than
> one that reports nothing, because you stop looking."

---

## 1:45 — The dashboard (90s)

Open `http://localhost:3000` (or `:30080` for the cluster).

1. **Overview** — risk score, severity breakdown, recent scans.
2. **A finding's detail page** — show the occurrence history.

> "The database keeps one row per distinct problem, keyed by a deterministic id,
> plus a row per scan that saw it. That split is what lets it answer *how long*
> — this bucket has been public since the 4th of August, not just 'is public'."

3. **Suppress a finding**, then return to the overview.

> "Now watch the headline number. It hasn't moved.
>
> Triage is a human overlay — it never touches the scanner's own claim about
> reality. Suppressing a finding hides it from the default view and changes
> nothing about whether the bucket is still public. The overview reports the
> filtered count, the true total, and how many are hidden, all three.
>
> A risk score that improved when you clicked 'suppress' would reward hiding
> problems instead of fixing them. For a posture tool that's not a rounding
> error, it's the whole product being wrong."

---

## 3:15 — The ML layer (90s)

```bash
npm run ml:evaluate
```

> "Two detectors on the same data with the *same alert budget* — twenty alerts
> each. An Isolation Forest, and a dependency-free statistical control using
> robust z-scores.
>
> The control exists to answer the question nobody usually asks: does the
> machine learning actually earn its place?"

Point at the results table:

> "On recall, it doesn't. Both find four of the five injected attacks.
>
> The forest wins somewhere else: it **repeats itself less**. The statistical
> model spends twelve of its twenty alerts re-reporting the same nightly backup
> job, because a per-feature threshold has no concept of recurrence. The forest
> spends three — thirty near-identical batch windows form a dense cluster, and
> a dense cluster is not *isolated*.
>
> That's the difference between a tool someone keeps reading and one they mute
> in week two. And a muted detector's real recall is zero, whatever its recall
> column says."

Then the missed scenario:

> "Neither catches `off_hours_access`, and that's by design. It's the
> deliberately weak case — ordinary work, usual address, usual region, only the
> clock is wrong. It's there to test whether one weak signal is enough. It
> isn't, and the evaluation reports that instead of tuning until it disappears.
>
> All of this is synthetic data generated by the project's own rules, so it
> demonstrates the pipeline works — it isn't a claim about accuracy on a real
> AWS account. The evaluation prints that caveat itself, so the number can't be
> quoted without it."

---

## 4:45 — Kubernetes and hardening (60s)

```bash
npm run k8s:status
```

> "Two dashboard replicas, Postgres as a StatefulSet, migrations as a Job."

> "The migrations run as a Job rather than at application startup, because
> `ALTER TABLE` and `DROP` mean the ability to destroy every stored finding —
> and a long-running web process shouldn't hold that for its whole lifetime just
> because it needed it for two seconds at boot."

Then the part worth the airtime:

```bash
kubectl apply -f k8s/test/netpol-probe.yaml
kubectl logs -n cloudsentinel netpol-probe   # after it completes
```

> "That's a pod without the database-client label trying to open a connection to
> Postgres. Blocked.
>
> This runs in CI on every push, and it's the check I'd most want to point at.
> A NetworkPolicy is accepted and stored by *any* cluster whether or not the
> network plugin actually implements it — no warning either way. So it can look
> perfectly applied and be doing nothing.
>
> A security control that's believed to be active and is in fact absent is worse
> than a known gap, because nobody goes looking for it. That's precisely the
> class of mistake this whole project exists to find in other people's
> infrastructure — so I wasn't going to ship an unverified one of my own."

If there is time, one more:

```bash
curl -i -X POST http://localhost:30080/api/auth/logout \
  -H "Origin: https://attacker.test"
```

> "403. Every state-changing route checks the Origin against the host it was
> actually addressed to. The `SameSite=strict` cookie already covers most of
> this — but that layer is enforced entirely by the browser, and the server
> doesn't get to choose the browser."

---

## 5:45 — Close (20s)

> "Roughly 390 unit tests, no test framework — just Node's built-in runner —
> plus database integration tests and a real cluster deployment in CI.
>
> The threat model and the known limitations are written up in SECURITY.md,
> including the parts that aren't finished: the NodePort still serves plain
> HTTP, and the login rate limiter is per-process, so it doesn't hold across
> replicas. Both are documented in the files they affect rather than left for
> someone to find."

---

## If it needs to be three minutes

Keep sections **1:45 (suppression)** and **4:45 (the NetworkPolicy probe)**, and
cut the rest to a single sentence each. Those two are the ones that show
judgement rather than output — one is a product decision that resists a
tempting shortcut, the other is refusing to trust a control without evidence.
Everything else is a feature list.
