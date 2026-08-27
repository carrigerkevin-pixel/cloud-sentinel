/**
 * CloudSentinel — CloudTrail-style activity log model.
 *
 * This file defines the shape of the *behavioural* data CloudSentinel analyses:
 * a stream of API-call records, modelled on AWS CloudTrail. It contains types
 * only — no imports, no logic, nothing that runs at runtime.
 *
 * Where it sits in the architecture: this is the entry point to stage three,
 * the ML anomaly layer, and it is the boundary between the two languages in
 * this project.
 *
 *   lib/logs/generator.ts  --> CloudTrailEvent[] --> fixtures/cloudtrail.json
 *          (TypeScript)                                      |
 *                                                            v
 *                                              ml/features.py, ml/detect.py
 *                                                        (Python)
 *                                                            |
 *                                                            v
 *                                              anomalies --> Postgres --> dashboard
 *
 * Because the Python side parses these records by field name, **this file is a
 * cross-language contract**. Renaming a field here silently breaks
 * `ml/features.py`, which has no way to type-check against TypeScript. Any
 * change to the field names below has to be made in both places at once; the
 * Python module documents the same contract from its side.
 *
 * Why phase 3 (the rule engine) is not enough on its own, which is the reason
 * this layer exists at all:
 *
 *   A rule engine reads *configuration* — is this bucket public, is this port
 *   open. Configuration is a snapshot, and some of the most damaging things an
 *   attacker does never change it. Credentials stolen from a developer laptop
 *   produce API calls that are individually legitimate and individually
 *   authorized: `GetObject` on a bucket the user may read, `ListUsers` by a
 *   user with `iam:ListUsers`. No rule can flag them, because nothing is
 *   misconfigured. What gives the attacker away is the *pattern* — the calls
 *   come at 3am from an IP in a country the account has never seen, and they
 *   walk through IAM in a sequence this principal has never performed. That is
 *   a behavioural question, and it needs behavioural data.
 *
 * On fidelity: these records are a deliberate *subset* of a real CloudTrail
 * event, which has around forty fields. Every field kept below feeds at least
 * one extracted feature in `ml/features.py`; fields that no feature reads
 * (`eventVersion` aside, which is kept for realism) are omitted rather than
 * populated with plausible-looking noise. Modelling fields nothing consumes
 * would make the fixture bigger, the diffs longer, and the honesty of the
 * exercise worse — it would imply an analysis depth that does not exist.
 *
 * SECURITY: every record produced under these types is **synthetic**. There is
 * no real account, no real principal, and no real IP address involved — the
 * account id is a documentation-range placeholder and the addresses come from
 * the ranges RFC 5737 reserves for examples. Nothing here should ever be
 * pointed at a real CloudTrail export without re-reading the privacy note in
 * lib/logs/generator.ts first: a genuine trail is among the most sensitive
 * artefacts an AWS account produces, and it is not something to commit to a
 * public portfolio repository.
 */

// ---------------------------------------------------------------------------
// Who performed the call
// ---------------------------------------------------------------------------

/**
 * The identity that made an API call.
 *
 * CloudTrail's real `userIdentity` block is a union whose shape depends on
 * `type`, and the three variants modelled here are the ones that matter for
 * behavioural analysis:
 *
 *   - `IAMUser`     — a long-lived user with an access key or console password.
 *     The most interesting case, because long-lived credentials are the ones
 *     that get stolen and reused.
 *   - `AssumedRole` — a temporary session from `sts:AssumeRole`. Normal for
 *     automation, and also the thing an attacker pivots into after escalating.
 *   - `Root`        — the account root user. Any activity at all is worth
 *     looking at; CIS explicitly recommends alerting on root usage.
 *
 * This is modelled as a flat interface with optional fields rather than a
 * discriminated union, unlike lib/types/resource.ts. The reason is that this
 * type mirrors an *external* JSON format that CloudSentinel does not control:
 * the analysis reads `arn` and `type` and largely ignores the rest, so the
 * compile-time narrowing a union would buy is not worth forcing every consumer
 * to switch on a variant it does not care about.
 */
export interface UserIdentity {
  /** Which kind of principal made the call. */
  type: "IAMUser" | "AssumedRole" | "Root";

  /**
   * AWS's opaque internal id for the principal (`AIDA...`, `AROA...`).
   *
   * Recorded for realism and never used as a key. The ARN is the join key
   * throughout this project instead, because a principal id is unreadable in a
   * dashboard and gives an analyst nothing to act on.
   */
  principalId: string;

  /**
   * The full ARN of the caller — **the grouping key for all analysis**.
   *
   * Every feature in `ml/features.py` is computed per-ARN, because "unusual"
   * only means anything relative to a specific principal's own history. Ten
   * `GetObject` calls in an hour is unremarkable for a backup service and
   * strange for a finance analyst who normally touches the console twice a day.
   * A model trained on account-wide averages would learn the behaviour of
   * whichever principal is busiest and flag everyone else as anomalous.
   */
  arn: string;

  /** The 12-digit account id. Always the synthetic placeholder — see header. */
  accountId: string;

  /**
   * The IAM user name, for `IAMUser` callers.
   *
   * `undefined` for `AssumedRole` and `Root`, matching CloudTrail: a role
   * session has a session name instead, and root has no user name at all.
   */
  userName?: string;

  /**
   * For `AssumedRole`, the name given to the session at `AssumeRole` time.
   *
   * `undefined` for other identity types.
   */
  sessionName?: string;
}

// ---------------------------------------------------------------------------
// The event
// ---------------------------------------------------------------------------

/**
 * One API call, as CloudTrail would record it.
 *
 * Field names deliberately keep AWS's `camelCase` spelling rather than being
 * renamed to project conventions. Anyone who has read a real trail can read
 * this, and a future version that ingests genuine CloudTrail JSON will need no
 * translation layer.
 */
export interface CloudTrailEvent {
  /**
   * CloudTrail's own schema version, currently `"1.11"` in real trails.
   *
   * Carried for realism and never read. It is the one field kept despite
   * feeding no feature, because a record that omitted it would not round-trip
   * through a tool expecting real CloudTrail.
   */
  eventVersion: string;

  /**
   * Unique id for this event, in UUID form.
   *
   * Used as the join key between a generated event and the ground-truth labels
   * in {@link AnomalyLabel.eventIds}, which is what lets the evaluation say
   * *which* events an injected attack consisted of.
   */
  eventID: string;

  /**
   * When the call happened, as an ISO 8601 string in UTC, ending in `Z`.
   *
   * UTC is not a stylistic choice here. Two of the five detection features are
   * time-of-day based ("is this outside the principal's normal hours?"), and a
   * mix of offsets in the data would put the same wall-clock hour in different
   * buckets depending on who wrote the record. The generator emits UTC only and
   * the Python side parses it as UTC only; a principal's *local* working hours
   * are modelled explicitly as a UTC offset on its profile instead.
   */
  eventTime: string;

  /**
   * The service endpoint, e.g. `"s3.amazonaws.com"`, `"iam.amazonaws.com"`.
   */
  eventSource: string;

  /**
   * The API action, e.g. `"GetObject"`, `"AttachUserPolicy"`, `"ConsoleLogin"`.
   *
   * Together with `eventSource` this is what the sensitive-action feature keys
   * off: a small set of IAM and STS action names carries most of the signal for
   * privilege escalation.
   */
  eventName: string;

  /** The region the call was made in, e.g. `"us-east-1"`. */
  awsRegion: string;

  /**
   * The caller's IP address, or an AWS service principal for service-initiated
   * calls.
   *
   * Always drawn from the RFC 5737 documentation ranges (`192.0.2.0/24`,
   * `198.51.100.0/24`, `203.0.113.0/24`), which are reserved for examples and
   * routed nowhere. That matters for a public repository: an invented-looking
   * address in a committed fixture can easily belong to somebody real, and
   * publishing a file that appears to accuse a genuine IP of credential theft
   * is a concrete harm even when the data is fake.
   */
  sourceIPAddress: string;

  /**
   * The client that made the call — an SDK version, the CLI, or the console.
   *
   * A weak signal on its own and not currently extracted as a feature, but kept
   * because it is the field an analyst reads first when triaging a flagged
   * event, and a dashboard that could not show it would send them back to the
   * raw log.
   */
  userAgent: string;

  /**
   * Whether the call only read state.
   *
   * Drives the write-to-read ratio feature. A principal that normally only
   * reads and suddenly starts writing is one of the clearer behavioural
   * signals available, and it is cheap to compute.
   */
  readOnly: boolean;

  /**
   * `"Management"` for control-plane calls, `"Data"` for object-level calls.
   *
   * Real accounts log data events only if explicitly enabled, and the volume
   * difference is enormous. Both are generated here because the exfiltration
   * scenario is a data-event pattern and would be invisible in a
   * management-only trail.
   */
  eventCategory: "Management" | "Data";

  /**
   * The AWS error code when the call failed, e.g. `"AccessDenied"`.
   *
   * `undefined` on success — matching CloudTrail, which omits the field
   * entirely rather than sending null.
   *
   * This is the single highest-signal field in the record. A burst of
   * `AccessDenied` from one principal is what permission enumeration looks
   * like: an attacker with stolen credentials does not know what those
   * credentials can do, so they find out by trying, and most attempts fail.
   * Legitimate users rarely call APIs they lack permission for, because their
   * tooling was built around what they can already do.
   */
  errorCode?: string;

  /** Human-readable detail accompanying `errorCode`. `undefined` on success. */
  errorMessage?: string;

  /** Who made the call. See {@link UserIdentity}. */
  userIdentity: UserIdentity;

  /**
   * A small, action-appropriate subset of the call's parameters.
   *
   * `null` for actions that take none. Real CloudTrail records the full request
   * with sensitive values redacted; this keeps only enough to make a flagged
   * event legible on the dashboard — which bucket, which user, which policy.
   *
   * SECURITY: in a real trail this field is the one most likely to contain
   * something sensitive, since AWS's redaction covers known-secret parameters
   * and not, say, an object key that happens to be a customer name. Any future
   * ingestion of genuine CloudTrail should treat this field as untrusted and
   * potentially confidential rather than rendering it straight into a page.
   */
  requestParameters: Record<string, string | number | boolean> | null;
}

// ---------------------------------------------------------------------------
// Ground truth
// ---------------------------------------------------------------------------

/**
 * The attack patterns the generator can inject.
 *
 * Each one is a recognisable real-world technique rather than generic noise,
 * and each is designed to be invisible to the phase 3 rule engine — none of
 * them requires a single misconfiguration to be present. That is the point of
 * the whole layer: these are the attacks a posture scanner cannot see.
 *
 *   - `privilege_escalation` — a principal that has never touched IAM begins
 *     calling `AttachUserPolicy` / `PutUserPolicy` / `CreatePolicyVersion`.
 *     This is the classic post-compromise move: make the foothold permanent and
 *     more powerful. Maps loosely to MITRE ATT&CK T1098 (Account Manipulation).
 *   - `off_hours_access` — sustained activity from a nine-to-five principal in
 *     the middle of its own night. Weak alone, which is exactly why it is
 *     included: it tests whether the model can combine a weak signal with
 *     others rather than relying on one obvious giveaway.
 *   - `new_geo_login` — `ConsoleLogin` and follow-on calls from a region and IP
 *     range this principal has never used. The "impossible travel" signal.
 *   - `credential_abuse` — a burst of `AccessDenied` failures across many
 *     services, i.e. someone mapping what a stolen credential can reach.
 *   - `data_exfiltration` — a volume spike of `GetObject` far beyond the
 *     principal's normal read rate, with unusually broad object coverage.
 *
 * Adding a member here is a breaking change for the dashboard, which maps each
 * value to a label and an explanation; the compiler will point at every place
 * that needs updating.
 */
export type AnomalyScenario =
  | "privilege_escalation"
  | "off_hours_access"
  | "new_geo_login"
  | "credential_abuse"
  | "data_exfiltration";

/**
 * A record of one injected attack — the *answer key* for evaluation.
 *
 * The single most important property of this type is where it does **not** go.
 * Labels are written to a separate file from the events, and neither
 * `ml/features.py` nor `ml/detect.py` opens that file. Only `ml/evaluate.py`
 * reads it, and only after detection has finished.
 *
 * That separation is what makes the reported precision and recall worth
 * quoting. Anomaly detection here is *unsupervised*: the model is shown
 * unlabelled activity and has to decide what looks strange on its own. If the
 * labels were available at training time the model could trivially learn to
 * predict them, and the resulting "98% accurate" claim would measure nothing
 * except that the answers had been left in the exam room. Keeping the answer
 * key in a different file is a cheap structural guarantee that this cannot
 * happen by accident, which is much stronger than a comment asking people not
 * to do it.
 */
export interface AnomalyLabel {
  /** Which technique was injected. See {@link AnomalyScenario}. */
  scenario: AnomalyScenario;

  /**
   * The ARN of the principal the attack was performed as.
   *
   * Detection is per-principal-per-hour, so this plus the time window is what a
   * detection has to match to count as a true positive.
   */
  principalArn: string;

  /** ISO 8601 UTC timestamp of the first event in the attack. */
  startTime: string;

  /** ISO 8601 UTC timestamp of the last event in the attack. */
  endTime: string;

  /**
   * The `eventID`s that make up this attack.
   *
   * Kept so the dashboard can show exactly which calls were involved, and so a
   * test can assert the injection actually produced events rather than silently
   * generating an empty scenario.
   */
  eventIds: string[];

  /**
   * A one-line plain-language description of what was injected.
   *
   * Written for a human reading the evaluation output, so it names the concrete
   * behaviour ("14 GetObject calls in 20 minutes, 30x the usual rate") rather
   * than restating the scenario name.
   */
  description: string;
}

// ---------------------------------------------------------------------------
// The generated bundle
// ---------------------------------------------------------------------------

/**
 * Provenance for a generated log, written into both output files.
 *
 * Exists so a fixture on disk can answer "where did this come from and can I
 * reproduce it?" without anyone having to guess. Regenerating with the recorded
 * `seed` and `days` reproduces the file byte for byte.
 */
export interface ActivityLogMetadata {
  /** The seed passed to {@link import("../util/random.ts").createRandom}. */
  seed: string;

  /** ISO 8601 UTC timestamp of the earliest event the run could produce. */
  startTime: string;

  /** How many days of activity were generated. */
  days: number;

  /** Total number of events in the log. */
  eventCount: number;

  /** Number of distinct principals that appear. */
  principalCount: number;

  /**
   * When the file was generated.
   *
   * Deliberately **not** the current wall-clock time: it is derived from the
   * seed and the configured start date instead. A real timestamp here would
   * change on every regeneration, so a fixture that was otherwise identical
   * would still show a diff, and the "regenerating produces no change" check
   * that guards determinism could never pass.
   */
  generatedAt: string;
}

/**
 * The event file: everything the detector is allowed to see.
 *
 * This is what `fixtures/cloudtrail.json` contains and what `ml/features.py`
 * reads. It carries no labels — see {@link AnomalyLabel} for why that matters.
 */
export interface ActivityLog {
  metadata: ActivityLogMetadata;

  /**
   * Every generated event, sorted by `eventTime` ascending.
   *
   * Sorted because that is how a real trail arrives and because it makes the
   * committed fixture diffable: an unsorted file would reshuffle on every
   * regeneration even with identical content. Attack events are interleaved
   * with normal traffic in this ordering rather than appended, so their
   * position in the file gives nothing away.
   */
  events: CloudTrailEvent[];
}

/**
 * The answer-key file: what was actually injected.
 *
 * Written to a separate path from {@link ActivityLog} and read only by
 * `ml/evaluate.py`, after detection has already produced its results.
 */
export interface ActivityLabels {
  metadata: ActivityLogMetadata;

  /** One entry per injected attack, sorted by `startTime` ascending. */
  labels: AnomalyLabel[];
}
