r"""CloudSentinel — behavioural feature extraction.

Turns a stream of CloudTrail-style events into a numeric matrix that an anomaly
detector can work on: one row per principal per hour, fourteen columns
describing how that hour compared with how that principal normally behaves.

Where it sits in the architecture: the first stage of the ML layer.

    lib/logs/generator.ts --> fixtures/cloudtrail.json
                                        |
                                        v
                              [ this file: features.py ]
                                        |
                          +-------------+-------------+
                          v                           v
                  baseline.py                     detect.py
              (robust z-scores)             (Isolation Forest)
                          \                           /
                           +----------> evaluate.py <+

Run directly to inspect what it produces without running any model:

    npm run ml:features
    ml/.venv/bin/python ml/features.py --input fixtures/cloudtrail.json

===============================================================================
The cross-language contract
===============================================================================

The field names read below (``eventTime``, ``userIdentity.arn``, ``eventName``,
``errorCode``, ...) are defined in ``lib/types/cloudtrail.ts`` and produced by
``lib/logs/generator.ts``. Python cannot type-check against TypeScript, so a
rename on that side surfaces here as a ``KeyError`` at runtime. Both files carry
this warning; there is a test in ``lib/logs/generator.test.ts`` that asserts the
field names still exist, which is the closest thing to a compile-time check the
boundary allows.

===============================================================================
Why the features are relative rather than absolute
===============================================================================

Almost every column below is a *ratio* or a *rarity*, not a raw count. That is
the central design decision of this file and it comes straight from the control
group in the generator.

An absolute feature such as "made more than 100 calls this hour" cannot work,
because the account contains a backup role that makes several hundred calls
every single night, legitimately. An absolute rule flags it thirty times a
month, the operator learns the tool cries wolf, and the tool stops being read
long before it ever sees a real intrusion. The same argument applies to "made a
sensitive IAM call", which is ``dave-admin``'s ordinary job.

So the question each feature asks is never "is this a lot?" but "is this a lot
*for this principal*?" — 300 GetObject calls is a crisis for an analyst who
normally makes fourteen an hour, and a quiet afternoon for a backup job.

===============================================================================
Leave-one-window-out profiling
===============================================================================

There is a subtle trap in building the per-principal baseline: the attacks are
*in the data*. If a principal's profile is computed over its whole history, then
the escalation the model is supposed to catch is part of what taught the model
what "normal" looks like. Alice's nine IAM calls become evidence that Alice
sometimes calls IAM, and the novelty signal quietly dilutes itself.

Every count-based profile here is therefore computed *excluding the window being
scored*: the aggregate is built once, and each window's own contribution is
subtracted before that window is measured against it. Exactly right, and still
one pass — the naive version would rebuild the profile per window and be
quadratic.

The two distribution statistics that are not leave-one-out — the median and MAD
of hourly volume — do not need to be. Both are *robust*: the median has a 50%
breakdown point, meaning half the data would have to be attack windows before it
moved meaningfully. Five attack windows out of roughly seven hundred cannot
shift it, which is precisely why median and MAD are used here instead of mean
and standard deviation. A single 322-event exfiltration hour drags a mean
noticeably; it moves a median not at all.

SECURITY: this module only reads a local JSON file and does arithmetic. It makes
no network calls, touches no credentials, and imports nothing outside the
standard library and NumPy. The input is synthetic (see ``lib/logs/generator.ts``);
if genuine CloudTrail were ever substituted, note that these events are among the
most sensitive data an AWS account produces and the output of this file still
contains principal ARNs.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np

# =============================================================================
# Vocabulary
# =============================================================================

#: API actions that grant, extend, or persist access.
#:
#: These are the calls that turn a foothold into durable control of an account:
#: attaching a policy, minting an access key, rewriting a role's trust document.
#: The list is drawn from the standard privilege-escalation paths documented for
#: AWS IAM rather than invented.
#:
#: Note carefully what this set is *not* used for. It is never a rule on its own
#: — ``dave-admin`` calls half of these every day as his job. It feeds the
#: ``sensitive_novelty`` feature, which weighs the count against how much history
#: the principal has of doing exactly that. The action name alone carries almost
#: no information; the action name paired with an empty history carries a lot.
SENSITIVE_ACTIONS = frozenset(
    {
        "AttachUserPolicy",
        "AttachRolePolicy",
        "AttachGroupPolicy",
        "PutUserPolicy",
        "PutRolePolicy",
        "PutGroupPolicy",
        "CreatePolicyVersion",
        "SetDefaultPolicyVersion",
        "CreateAccessKey",
        "UpdateAccessKey",
        "CreateUser",
        "CreateRole",
        "CreateLoginProfile",
        "UpdateLoginProfile",
        "AddUserToGroup",
        "UpdateAssumeRolePolicy",
        "PassRole",
        "DeactivateMFADevice",
        "DeleteVirtualMFADevice",
    }
)

#: Request-parameter keys that name a distinct thing being acted upon.
#:
#: Used to count how many *different* resources a window touched, which is what
#: separates a bucket sweep (300 calls, 300 keys) from a stuck retry loop
#: (300 calls, one key). Without this, both look identical on volume alone.
RESOURCE_KEYS = ("key", "bucketName", "instanceId", "resourceId", "userName", "policyArn")

#: The feature columns, in the order they appear in the matrix.
#:
#: This ordering is part of the contract with ``detect.py`` and ``baseline.py``,
#: which index into the matrix and report feature names back as evidence. Adding
#: a column means appending here, never inserting in the middle.
FEATURE_NAMES: tuple[str, ...] = (
    "event_count",
    "volume_ratio",
    "distinct_actions",
    "unseen_action_rate",
    "error_rate",
    "error_excess",
    "write_ratio",
    "distinct_ips",
    "unseen_ip_rate",
    "unseen_region_rate",
    "hour_rarity",
    "sensitive_count",
    "sensitive_novelty",
    "distinct_resources",
)

#: Plain-language explanation of each feature, shown as evidence on the
#: dashboard and in the evaluation output.
#:
#: An anomaly score with no explanation is unusable: told only that an hour
#: scored -0.62, an analyst has nowhere to start. These strings are what turn a
#: number into something someone can act on, which is why they live next to the
#: features rather than in the UI.
FEATURE_DESCRIPTIONS: dict[str, str] = {
    "event_count": "number of API calls in the hour",
    "volume_ratio": "call volume relative to what this principal normally does at this hour of day",
    "distinct_actions": "number of different API actions used",
    "unseen_action_rate": "share of calls using actions this principal has never made",
    "error_rate": "share of calls that failed",
    "error_excess": "failure rate above this principal's normal background rate",
    "write_ratio": "share of calls that modified state rather than read it",
    "distinct_ips": "number of distinct source addresses",
    "unseen_ip_rate": "share of calls from address ranges never used before",
    "unseen_region_rate": "share of calls from regions never used before",
    "hour_rarity": "how unusual this hour of day is for this principal",
    "sensitive_count": "number of permission-granting or credential-creating calls",
    "sensitive_novelty": "sensitive calls weighed against this principal's history of making them",
    "distinct_resources": "number of different resources touched",
}

#: Windows with fewer events than this are dropped.
#:
#: A one-event hour has no meaningful internal structure: its error rate is 0 or
#: 1, its write ratio is 0 or 1, and its volume ratio is dominated by rounding.
#: Feeding those to a detector produces a haze of meaningless outliers that
#: buries the real ones. Every injected attack is comfortably above this floor —
#: the smallest is nine events — so nothing detectable is being discarded.
MIN_WINDOW_EVENTS = 3

#: Pseudo-observations added to every rate feature, pulling it toward the
#: principal's own historical rate.
#:
#: This is empirical-Bayes shrinkage, and it fixes the single largest source of
#: false positives found while building this layer.
#:
#: The problem: a rate computed over a handful of events is almost pure noise.
#: A four-call hour containing one permission error has an error rate of 0.25,
#: which against a 1% background looks like a catastrophe and is actually one
#: stale script. The first version of this file flagged a string of such windows
#: on both control principals, and they crowded genuine attacks out of the alert
#: budget.
#:
#: The fix is to treat the principal's historical rate as a prior and the
#: window's events as evidence updating it:
#:
#:     rate = (observed + k * prior) / (n + k)
#:
#: With k = 10, that four-call hour drops from 0.25 to 0.08 — the evidence is
#: too thin to move the estimate far. The thirty-one-call enumeration burst with
#: twenty-six denials only falls from 0.84 to 0.64, because thirty-one events is
#: enough evidence to overrule the prior. Small windows are damped, real signal
#: survives.
#:
#: k = 10 is chosen to be near the typical window size in this account (median
#: 17 events), so a window has to be at least averagely-sized before its own
#: evidence outweighs its history. Raising MIN_WINDOW_EVENTS instead would have
#: been cruder: it discards the quiet hours entirely, and an attacker making six
#: careful calls would fall straight through the gap.
SHRINKAGE_STRENGTH = 10.0


# =============================================================================
# Loading
# =============================================================================


def load_events(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Reads an activity log written by ``npm run logs:gen``.

    Args:
        path: the events file, normally ``fixtures/cloudtrail.json``.

    Returns:
        A ``(events, metadata)`` pair. ``metadata`` carries the seed and window
        that produced the log, so downstream output can record what it analysed.

    Raises:
        SystemExit: if the file is missing, with a message pointing at the
            command that creates it. This is a script-facing failure rather than
            an exception because the fix is always the same one command, and a
            traceback would bury it.
        ValueError: if the file is not valid JSON or lacks an ``events`` array —
            which means it is not the file this expects, and guessing would only
            produce a stranger error later.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        sys.exit(
            f"No activity log at {path}.\n"
            f"Generate one first:  npm run logs:gen"
        )

    if not isinstance(raw, dict) or not isinstance(raw.get("events"), list):
        raise ValueError(
            f"{path} does not look like a CloudSentinel activity log "
            "(expected an object with an 'events' array)"
        )

    return raw["events"], raw.get("metadata", {})


def _parse_time(value: str) -> datetime:
    """Parses an ISO 8601 timestamp into an aware UTC ``datetime``.

    The generator always emits a trailing ``Z``. ``fromisoformat`` accepts it
    directly on modern Python, but the explicit replacement below keeps this
    working if a log ever arrives with ``+00:00`` instead.

    Args:
        value: an ISO 8601 timestamp.

    Returns:
        A timezone-aware ``datetime`` in UTC.
    """
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _ip_prefix(address: str) -> str:
    """Reduces an IPv4 address to its /24 network.

    Grouping by /24 rather than by exact address is deliberate. Real people move
    between an office, a VPN and a home connection, and their address changes
    within a range without that meaning anything. Treating every new address as
    novel would make the geography features fire constantly; treating a whole
    new range as novel is the signal that actually corresponds to "somewhere
    else entirely".

    Args:
        address: an IPv4 address, or anything else.

    Returns:
        The first three octets joined by dots, or the input unchanged if it does
        not look like IPv4 — AWS records service principals such as
        ``s3.amazonaws.com`` in this field, and those are meaningful as-is.
    """
    parts = address.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return ".".join(parts[:3])
    return address


# =============================================================================
# Per-principal profiles
# =============================================================================


@dataclass
class PrincipalProfile:
    """Everything known about how one principal normally behaves.

    Built by aggregating all of that principal's events. Counters rather than
    sets throughout, because the leave-one-window-out arithmetic described in
    the module docstring needs to *subtract* a window's contribution — which
    requires knowing how many times something happened, not merely whether it
    did.
    """

    arn: str

    #: How many events the principal produced in each UTC hour, 0-23.
    hour_counts: np.ndarray = field(
        default_factory=lambda: np.zeros(24, dtype=np.float64)
    )

    #: How many *windows* the principal has at each UTC hour, 0-23.
    #:
    #: Paired with :attr:`hour_counts` to give the principal's typical volume at
    #: a given hour of day — which is what ``volume_ratio`` compares against.
    #: See the note on that feature for why the hour-of-day denominator matters
    #: so much more than it looks like it should.
    hour_window_counts: np.ndarray = field(
        default_factory=lambda: np.zeros(24, dtype=np.float64)
    )

    #: How often each API action was called.
    action_counts: Counter = field(default_factory=Counter)

    #: How often each source /24 was used.
    ip_counts: Counter = field(default_factory=Counter)

    #: How often each region was used.
    region_counts: Counter = field(default_factory=Counter)

    #: Total events, failed events, and sensitive-action calls.
    total_events: int = 0
    total_errors: int = 0
    total_sensitive: int = 0
    total_writes: int = 0

    #: Event count per hour window, kept to derive the robust volume statistics.
    window_sizes: list[int] = field(default_factory=list)

    #: Median events in an active hour. Robust to the attack windows in the data.
    median_volume: float = 1.0

    #: Median absolute deviation of the above, scaled to be comparable to a
    #: standard deviation.
    mad_volume: float = 1.0

    def finalise(self) -> None:
        """Computes the robust volume statistics once all events are counted.

        Uses median and MAD rather than mean and standard deviation because the
        log contains the very attacks being looked for. A single 322-event
        exfiltration hour moves a mean substantially and a median not at all —
        the median needs more than half the windows to be anomalous before it
        shifts, and five out of seven hundred is nowhere near that.
        """
        if not self.window_sizes:
            return

        sizes = np.asarray(self.window_sizes, dtype=np.float64)
        self.median_volume = float(np.median(sizes))

        # 1.4826 rescales the MAD so that, for normally distributed data, it
        # estimates the same quantity as the standard deviation. That makes the
        # z-scores in baseline.py interpretable on the usual scale.
        self.mad_volume = float(1.4826 * np.median(np.abs(sizes - self.median_volume)))

        # A principal whose hours are nearly all identical has a MAD of zero,
        # which would divide by zero downstream. The floor of 1 event says "we
        # cannot resolve differences finer than one call an hour", which is
        # honest and keeps the arithmetic finite.
        self.mad_volume = max(self.mad_volume, 1.0)
        self.median_volume = max(self.median_volume, 1.0)


def build_profiles(events: Sequence[dict[str, Any]]) -> dict[str, PrincipalProfile]:
    """Aggregates every principal's behaviour across the whole log.

    Args:
        events: the full event stream.

    Returns:
        One profile per principal ARN.
    """
    profiles: dict[str, PrincipalProfile] = {}
    window_counter: Counter = Counter()

    for event in events:
        arn = event["userIdentity"]["arn"]
        profile = profiles.get(arn)
        if profile is None:
            profile = PrincipalProfile(arn=arn)
            profiles[arn] = profile

        at = _parse_time(event["eventTime"])

        profile.hour_counts[at.hour] += 1
        profile.action_counts[event["eventName"]] += 1
        profile.ip_counts[_ip_prefix(event["sourceIPAddress"])] += 1
        profile.region_counts[event["awsRegion"]] += 1
        profile.total_events += 1

        if event.get("errorCode"):
            profile.total_errors += 1
        if event["eventName"] in SENSITIVE_ACTIONS:
            profile.total_sensitive += 1
        if not event.get("readOnly", True):
            profile.total_writes += 1

        window_counter[(arn, at.replace(minute=0, second=0, microsecond=0))] += 1

    for (arn, hour_start), count in window_counter.items():
        profiles[arn].window_sizes.append(count)
        profiles[arn].hour_window_counts[hour_start.hour] += 1

    for profile in profiles.values():
        profile.finalise()

    return profiles


# =============================================================================
# Windows
# =============================================================================


@dataclass
class Window:
    """One principal's activity during one UTC hour, with its feature vector."""

    principal_arn: str

    #: ISO 8601 UTC timestamp of the start of the hour.
    hour_start: str

    #: How many events fell in this window.
    event_count: int

    #: Feature values, keyed by the names in :data:`FEATURE_NAMES`.
    features: dict[str, float]

    #: The ids of the events in this window.
    #:
    #: Carried so a detection can point at the specific calls involved, and so
    #: ``evaluate.py`` can check a detection against the labelled event ids
    #: rather than guessing from timestamps alone.
    event_ids: list[str]

    #: A few representative action names, for display only.
    sample_actions: list[str]


def _group_windows(
    events: Sequence[dict[str, Any]],
) -> dict[tuple[str, datetime], list[dict[str, Any]]]:
    """Buckets events by principal and UTC hour.

    One hour is the window size throughout this layer. It is a compromise:
    shorter windows (five minutes) catch fast scripted bursts but give each
    window too few events for a rate to mean anything, while longer ones (a day)
    dilute a twenty-minute exfiltration into an otherwise ordinary Tuesday. An
    hour is long enough that ratios are stable and short enough that a burst
    still dominates its own window.

    The cost is real and worth stating: an attack deliberately spread thinly
    across many hours — a few calls each, for days — would stay under every
    per-hour threshold here. Defeating that needs sequence modelling rather than
    windowed aggregates, and it is out of scope for this layer.

    Args:
        events: the full event stream.

    Returns:
        A mapping from ``(principal_arn, hour_start)`` to that window's events.
    """
    grouped: dict[tuple[str, datetime], list[dict[str, Any]]] = {}

    for event in events:
        at = _parse_time(event["eventTime"])
        key = (
            event["userIdentity"]["arn"],
            at.replace(minute=0, second=0, microsecond=0),
        )
        grouped.setdefault(key, []).append(event)

    return grouped


def _shrink(observed: float, n: int, prior: float) -> float:
    """Shrinks an observed rate toward a prior, in proportion to the evidence.

    See :data:`SHRINKAGE_STRENGTH` for why every rate feature goes through this.
    In short: a rate measured over four events is noise, a rate measured over
    forty is evidence, and this weights them accordingly instead of pretending
    they are equally trustworthy.

    Args:
        observed: how many events in the window had the property.
        n: how many events were in the window.
        prior: the principal's historical rate for this property, excluding this
            window. Use 0.0 for novelty rates, where the prior genuinely is zero
            — a previously-unseen region is unseen by definition.

    Returns:
        The shrunk rate, in ``[0, 1]``.
    """
    return (observed + SHRINKAGE_STRENGTH * prior) / (n + SHRINKAGE_STRENGTH)


def _window_features(
    window_events: Sequence[dict[str, Any]],
    profile: PrincipalProfile,
    hour: int,
) -> dict[str, float]:
    """Computes the feature vector for one window.

    Every count-based comparison here subtracts this window's own contribution
    from the profile first, so a window is always measured against the
    principal's behaviour *excluding itself*. Without that subtraction an attack
    would partly define the baseline it is being compared to.

    Args:
        window_events: the events in this window. Never empty.
        profile: the principal's whole-log aggregate.
        hour: the UTC hour, 0-23, this window covers.

    Returns:
        A mapping from every name in :data:`FEATURE_NAMES` to its value.
    """
    count = len(window_events)

    actions = Counter(event["eventName"] for event in window_events)
    ips = Counter(_ip_prefix(event["sourceIPAddress"]) for event in window_events)
    regions = Counter(event["awsRegion"] for event in window_events)

    errors = sum(1 for event in window_events if event.get("errorCode"))
    writes = sum(1 for event in window_events if not event.get("readOnly", True))
    sensitive = sum(
        1 for event in window_events if event["eventName"] in SENSITIVE_ACTIONS
    )

    # --- History excluding this window -------------------------------------

    history_events = max(0, profile.total_events - count)
    history_errors = max(0, profile.total_errors - errors)
    history_sensitive = max(0, profile.total_sensitive - sensitive)

    unseen_actions = sum(
        n for name, n in actions.items() if profile.action_counts[name] - n <= 0
    )
    unseen_ips = sum(
        n for prefix, n in ips.items() if profile.ip_counts[prefix] - n <= 0
    )
    unseen_regions = sum(
        n for region, n in regions.items() if profile.region_counts[region] - n <= 0
    )

    # --- Hour rarity --------------------------------------------------------

    # The principal's share of activity in this hour of day, compared against a
    # perfectly flat 1/24 distribution.
    #
    # The comparison to uniform is what protects the automated control. A backup
    # role active around the clock has a share of roughly 1/24 in every hour, so
    # its rarity is 0 at 3am — correctly, because 3am is unremarkable *for it*.
    # A nine-to-five analyst has a share near zero at 3am and the rarity
    # approaches 1. A raw "is it night?" feature cannot tell those apart, and
    # would report the backup job every night for a month.
    hour_total = profile.hour_counts[hour] - count
    history_hour_total = max(1.0, float(profile.total_events - count))
    share = max(0.0, hour_total) / history_hour_total
    hour_rarity = 1.0 - min(1.0, share * 24.0)

    # --- Volume, relative to this hour of day -------------------------------

    # The denominator is what this principal normally does *at this hour*, not
    # its overall median hour. That distinction turned out to matter more than
    # anything else in this file, and it was found empirically rather than
    # predicted.
    #
    # The first version of this feature divided by the principal's overall
    # median volume. On the generated account that flagged the backup role's
    # 02:00 batch on almost every night of the month — the role does roughly six
    # times its usual work in that window, legitimately and predictably, so a
    # ratio against its all-hours median is ~6 every single night. It comfortably
    # out-scored two of the five real attacks, and would have consumed most of a
    # human's alert budget reporting a cron job.
    #
    # Dividing by the principal's typical volume *at that hour of day* removes
    # the entire class of problem: a scheduled batch is compared against its own
    # previous runs and scores ~1, while a genuine 20x spike in an hour the
    # principal normally works scores ~20. It costs one extra counter per
    # principal.
    #
    # The residual weakness, stated so nobody assumes otherwise: an attacker who
    # knows the schedule could hide inside the batch window, where the tolerance
    # is now much wider. Defeating that needs the volume broken down by action
    # and resource rather than counted, which is beyond this layer.
    hour_windows = max(0.0, profile.hour_window_counts[hour] - 1.0)
    if hour_windows > 0:
        typical_at_hour = max(0.0, hour_total) / hour_windows
    else:
        # No other window at this hour of day — the principal has never been
        # active then. Fall back to the overall median, and let `hour_rarity`
        # carry the "this hour is itself unusual" part of the signal.
        typical_at_hour = profile.median_volume

    volume_ratio = count / max(1.0, typical_at_hour)

    # --- Sensitive-action novelty ------------------------------------------

    # Weighs sensitive calls against how routinely this principal makes them.
    #
    # The 1000x scaling turns a small rate into a large divisor: an admin whose
    # history is 25% IAM writes gets a divisor of ~251, so even five sensitive
    # calls score about 0.02. An analyst who has never made one gets a divisor of
    # 1, so four sensitive calls score 4.0 — two orders of magnitude apart for
    # the identical API actions. This single feature is what separates the
    # privilege-escalation attack from the admin control.
    sensitive_rate = history_sensitive / max(1, history_events)
    sensitive_novelty = sensitive / (1.0 + sensitive_rate * 1000.0)

    # --- Distinct resources -------------------------------------------------

    resources: set[str] = set()
    for event in window_events:
        params = event.get("requestParameters") or {}
        for key in RESOURCE_KEYS:
            if key in params:
                resources.add(f"{key}={params[key]}")

    baseline_error_rate = history_errors / max(1, history_events)
    baseline_write_rate = (profile.total_writes - writes) / max(1, history_events)

    # Every rate below is shrunk toward this principal's own history, so a
    # four-event hour cannot manufacture an extreme rate out of one unlucky
    # call. The novelty rates use a prior of zero: an address range that has
    # never been seen has, by definition, a historical rate of zero, and the
    # shrinkage there serves only to damp tiny windows.
    error_rate = _shrink(errors, count, baseline_error_rate)

    return {
        "event_count": float(count),
        "volume_ratio": volume_ratio,
        "distinct_actions": float(len(actions)),
        "unseen_action_rate": _shrink(unseen_actions, count, 0.0),
        "error_rate": error_rate,
        # Clamped at zero: an hour with *fewer* errors than usual is not a
        # security signal, and letting it go negative would make a suspiciously
        # clean hour look as interesting as a suspiciously broken one.
        "error_excess": max(0.0, error_rate - baseline_error_rate),
        "write_ratio": _shrink(writes, count, baseline_write_rate),
        "distinct_ips": float(len(ips)),
        "unseen_ip_rate": _shrink(unseen_ips, count, 0.0),
        "unseen_region_rate": _shrink(unseen_regions, count, 0.0),
        "hour_rarity": hour_rarity,
        "sensitive_count": float(sensitive),
        "sensitive_novelty": sensitive_novelty,
        "distinct_resources": float(len(resources)),
    }


def extract_windows(events: Sequence[dict[str, Any]]) -> list[Window]:
    """Turns an event stream into scored-ready feature windows.

    Args:
        events: the full event stream from :func:`load_events`.

    Returns:
        One :class:`Window` per principal per active hour, sorted by time then
        principal so the output is deterministic. Windows with fewer than
        :data:`MIN_WINDOW_EVENTS` events are omitted — see that constant for why.

    Raises:
        ValueError: if the event stream is empty, which would otherwise produce
            an empty matrix and a confusing failure inside scikit-learn.
    """
    if not events:
        raise ValueError("cannot extract features from an empty event stream")

    profiles = build_profiles(events)
    grouped = _group_windows(events)

    windows: list[Window] = []

    for (arn, hour_start), window_events in grouped.items():
        if len(window_events) < MIN_WINDOW_EVENTS:
            continue

        features = _window_features(window_events, profiles[arn], hour_start.hour)

        windows.append(
            Window(
                principal_arn=arn,
                hour_start=hour_start.isoformat().replace("+00:00", "Z"),
                event_count=len(window_events),
                features=features,
                event_ids=[event["eventID"] for event in window_events],
                sample_actions=[
                    name
                    for name, _ in Counter(
                        event["eventName"] for event in window_events
                    ).most_common(5)
                ],
            )
        )

    windows.sort(key=lambda window: (window.hour_start, window.principal_arn))
    return windows


def to_matrix(windows: Sequence[Window]) -> np.ndarray:
    """Stacks window features into a 2-D array for the models.

    Args:
        windows: the windows to convert.

    Returns:
        An array of shape ``(len(windows), len(FEATURE_NAMES))``, with columns in
        :data:`FEATURE_NAMES` order.
    """
    return np.asarray(
        [[window.features[name] for name in FEATURE_NAMES] for window in windows],
        dtype=np.float64,
    )


# =============================================================================
# CLI
# =============================================================================


def _summarise(windows: Sequence[Window]) -> None:
    """Prints a short description of the extracted features.

    Exists so the feature stage can be inspected on its own, before any model is
    involved. When a detection looks wrong the first question is always whether
    the features were right, and being able to answer that without running a
    model saves a lot of guessing.
    """
    matrix = to_matrix(windows)
    principals = sorted({window.principal_arn for window in windows})

    print(f"\nWindows:    {len(windows):,} (principal x hour)")
    print(f"Principals: {len(principals)}")
    print(f"Features:   {len(FEATURE_NAMES)}\n")

    name_width = max(len(name) for name in FEATURE_NAMES)
    print(f"  {'feature'.ljust(name_width)}  {'median':>10} {'p99':>10} {'max':>10}")
    print(f"  {'-' * name_width}  {'-' * 10} {'-' * 10} {'-' * 10}")

    for index, name in enumerate(FEATURE_NAMES):
        column = matrix[:, index]
        print(
            f"  {name.ljust(name_width)}  "
            f"{np.median(column):>10.3f} "
            f"{np.percentile(column, 99):>10.3f} "
            f"{column.max():>10.3f}"
        )

    print("\n  Windows per principal:")
    for arn in principals:
        count = sum(1 for window in windows if window.principal_arn == arn)
        print(f"    {arn.split('/')[-1]:<34} {count:>5}")
    print()


def main() -> None:
    """Entry point for ``npm run ml:features``."""
    parser = argparse.ArgumentParser(
        description="Extract behavioural features from a CloudSentinel activity log."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("fixtures/cloudtrail.json"),
        help="activity log to read (default: fixtures/cloudtrail.json)",
    )
    args = parser.parse_args()

    events, metadata = load_events(args.input)
    print(
        f"\nRead {len(events):,} events from {args.input} "
        f"(seed {metadata.get('seed', '?')}, {metadata.get('days', '?')} days)"
    )

    _summarise(extract_windows(events))


if __name__ == "__main__":
    main()
