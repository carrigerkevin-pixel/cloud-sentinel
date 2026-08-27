r"""CloudSentinel — anomaly detection.

Runs both detectors over the extracted behavioural features and writes the
flagged windows to JSON for the TypeScript layer to ingest.

    npm run ml:detect
    npm run ml:detect -- --contamination 0.005
    npm run ml:detect -- --input fixtures/cloudtrail.json --out fixtures/anomalies.json

Where it sits in the architecture: the middle of the ML layer.

    features.py ---> [ this file: detect.py ] ---> fixtures/anomalies.json
         |                     |                            |
         |                     v                            v
         +------------> baseline.py                 lib/anomalies/ingest.ts
                                                            |
                                                            v
                                                   Postgres --> dashboard

===============================================================================
Why an Isolation Forest
===============================================================================

The problem is unsupervised: there are no labels at training time, so nothing
can be fitted to "what an attack looks like". What is available is a large pile
of ordinary behaviour and the assumption that intrusions are rare and different.

An Isolation Forest is built directly on that assumption. It repeatedly splits
the data on a random feature at a random threshold and asks how many splits it
takes to isolate each point. Points in dense regions — ordinary hours, which
look like thousands of other ordinary hours — need many splits. Points sitting
away from everything else fall out in a handful. The average path length across
many random trees becomes the anomaly score.

Three properties make it the right fit here rather than the fashionable choice:

  1. **It needs no labelled attacks**, which is the entire situation.
  2. **It is scale-invariant.** Because it splits on thresholds rather than
     measuring distances, no feature standardisation step is required — and a
     standardisation step is one more thing to get subtly wrong, since the
     scaler would have to be fitted on data that contains the attacks.
  3. **It handles recurring clusters correctly**, which turned out to be the
     property that actually matters here — and it is the one place the ML
     measurably beats the statistical baseline.

     The backup role's nightly 02:00 batch is a large, legitimate volume spike
     that happens thirty times in thirty days. Those thirty windows sit close
     together in feature space, so no single one is *isolated*, and the forest
     scores them unremarkably. A per-feature threshold has no notion of
     recurrence: it sees thirty spikes and reports thirty alerts.

     Measured on the generated account, at an equal budget of twenty alerts
     each: both models find four of the five injected attacks, so the ML wins
     nothing on recall. But the statistical baseline spends **twelve of its
     twenty alerts** re-reporting that one cron job, while the forest spends
     three. That is the difference between a tool somebody keeps reading and a
     tool somebody mutes in week two — and a muted detector's real recall is
     zero regardless of what its recall column says.

     This is the honest answer to "does the machine learning earn its place?".
     It does, but not for the reason the pitch usually given: not by catching
     more, by repeating itself less.

===============================================================================
The alert budget: how the two models are compared fairly
===============================================================================

Comparing detectors is easy to do dishonestly. Set one model's threshold
generously and it "catches more attacks" — while burying the analyst in false
positives that the comparison never shows.

So both models here are given **the same budget**: whatever ``--contamination``
implies as a number of windows, each model flags exactly that many, choosing its
own highest-scoring ones. The question then becomes the one that matters
operationally — *given a fixed amount of human attention, which detector spends
it better?* — rather than the meaningless "which detector alerts more".

This also reframes ``contamination`` correctly. It looks like a statistical
parameter and is really a staffing decision: it is the number of hours per month
somebody is willing to investigate. The default of 1% of windows is roughly
twenty alerts for a month of activity across six principals, which is a
plausible load for one person. It is not an estimate of how much crime is in the
data, and treating it as one would be a mistake.

===============================================================================
Where the explanations come from
===============================================================================

An Isolation Forest cannot explain itself. Its output is an average path length,
and there is no meaningful way to point at a column and say "this is the one
that made it anomalous" — the whole mechanism is about the joint position of the
point, not any single axis.

That is a genuine operational problem, not a cosmetic one. An alert reading
"principal X, 03:00, score -0.62" gives an analyst nowhere to start; they will
either ignore it or spend an hour reconstructing the reason by hand, and after a
few of those they stop reading the alerts.

So every detection carries evidence taken from the *baseline* model's
per-feature robust z-scores: the three features that were most extreme for that
window, in plain language. The forest decides **what** to flag; the statistical
model explains **why** it looks strange. Pairing them costs nothing — the
baseline scores are computed anyway for the comparison — and it turns an opaque
number into "call volume was 22x this principal's normal hour, against 322
distinct objects".

The limitation is stated honestly on the dashboard and here: those features are
what made the window statistically unusual, which is strong evidence but not the
forest's actual internal reasoning. Claiming otherwise would be a nicer story
and a false one.

SECURITY: reads and writes local files only — no network, no credentials, no
database. The output contains principal ARNs and event ids but no request
contents. ``random_state`` is fixed so a rerun on the same input produces
identical detections; a detector whose output changed between runs would make
"this alert is new" impossible to determine.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Sequence

import numpy as np
from sklearn.ensemble import IsolationForest

from baseline import BaselineScore, score_windows
from features import (
    FEATURE_DESCRIPTIONS,
    FEATURE_NAMES,
    Window,
    extract_windows,
    load_events,
    to_matrix,
)

# =============================================================================
# Constants
# =============================================================================

#: Number of trees in the forest.
#:
#: 200 rather than the scikit-learn default of 100. The score is an average over
#: trees, so more trees means less run-to-run variance in the ranking near the
#: threshold — which is where the marginal alerts live and where instability
#: would be most annoying. At this data size the extra cost is milliseconds.
N_ESTIMATORS = 200

#: Fixed seed for the forest's randomness.
#:
#: Not optional. The forest picks random split features and thresholds, so
#: without a fixed seed the same input would yield slightly different rankings
#: each run, alerts would appear and disappear on rerun, and it would be
#: impossible to tell a genuinely new detection from scoring noise.
RANDOM_STATE = 20260826

#: Default share of windows to flag. See the alert-budget discussion above —
#: this is an operational capacity choice, not an estimate of attack prevalence.
DEFAULT_CONTAMINATION = 0.01

#: Length of a feature window, matching ``features._group_windows``.
WINDOW_HOURS = 1

#: Evidence features below this z-score are not reported.
#:
#: Roughly two robust standard deviations. Listing a feature that was barely
#: unusual as a "reason" trains the reader to distrust the evidence section.
MIN_EVIDENCE_Z = 2.0


# =============================================================================
# Scoring
# =============================================================================


def run_isolation_forest(
    matrix: np.ndarray, contamination: float
) -> np.ndarray:
    """Fits an Isolation Forest and returns a per-window anomaly score.

    No feature scaling is applied, deliberately. The forest splits on thresholds
    rather than distances, so it is invariant to the scale of each column, and
    adding a scaler would mean fitting one on data that contains the attacks —
    an extra chance to leak the anomalies into the definition of normal for no
    benefit.

    Args:
        matrix: window-by-feature values from :func:`features.to_matrix`.
        contamination: the expected anomaly share, passed through to
            scikit-learn. It sets the model's internal offset; the actual
            flagging in :func:`detect` uses the alert budget instead, so this
            mainly affects the sign convention of ``decision_function``.

    Returns:
        One score per window, higher meaning more anomalous. This is the
        negation of scikit-learn's ``decision_function``, which is oriented the
        other way — flipping it here means every score in this pipeline, from
        both models, points the same direction, and nothing downstream has to
        remember which convention applies to which model.
    """
    forest = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=contamination,
        random_state=RANDOM_STATE,
        # Use every window to build each tree. The default subsamples to 256,
        # which is a speed optimisation for large datasets; with ~2,000 windows
        # the full sample is cheap and removes a source of variance.
        max_samples=min(1024, matrix.shape[0]),
        n_jobs=1,
    )
    forest.fit(matrix)

    return -forest.decision_function(matrix)


def rank_percentile(scores: np.ndarray) -> np.ndarray:
    """Converts raw scores to a 0-100 rank percentile.

    Used for display only. The raw scores from the two models are on completely
    different scales — a robust z-score of 22 and a forest score of 0.19 are not
    comparable numbers — and a dashboard showing either raw value would be
    meaningless to a reader.

    Rank-based rather than min-max normalisation on purpose: a single extreme
    outlier compresses every other value into the bottom of a min-max range, so
    the exfiltration window would make all nineteen other alerts look like a
    score of 2. Ranks are immune to that.

    Args:
        scores: raw scores, higher meaning more anomalous.

    Returns:
        Percentiles in ``[0, 100]``, aligned with the input.
    """
    order = scores.argsort().argsort().astype(np.float64)
    if len(scores) <= 1:
        return np.full_like(scores, 100.0)
    return 100.0 * order / (len(scores) - 1)


def build_evidence(score: BaselineScore) -> list[dict[str, Any]]:
    """Turns a baseline score into the evidence list attached to a detection.

    See the module docstring for why the forest's detections are explained using
    the statistical model's per-feature scores rather than the forest's own
    internals.

    Args:
        score: the window's baseline result.

    Returns:
        Up to three entries, worst first, each naming a feature, its z-score and
        a plain-language description. Possibly empty — a window the forest
        isolated on a *combination* of unremarkable features genuinely has no
        single feature worth pointing at, and inventing one would be worse than
        saying nothing.
    """
    return [
        {
            "feature": name,
            "zScore": round(value, 2),
            "description": FEATURE_DESCRIPTIONS[name],
        }
        for name, value, _ in score.contributors
        if value >= MIN_EVIDENCE_Z
    ]


# =============================================================================
# Detection
# =============================================================================


def detect(
    windows: Sequence[Window],
    matrix: np.ndarray,
    contamination: float,
) -> dict[str, Any]:
    """Runs both detectors and assembles the output document.

    Args:
        windows: the extracted windows.
        matrix: their feature values.
        contamination: share of windows each model may flag. See the alert
            budget discussion in the module docstring.

    Returns:
        The full result document, ready to serialise.

    Raises:
        ValueError: if there are too few windows for a meaningful budget — with
            fewer than 20 windows a 1% budget rounds to one alert and the
            comparison between models says nothing.
    """
    if len(windows) < 20:
        raise ValueError(
            f"only {len(windows)} windows; need at least 20 for a meaningful "
            "detection budget (generate a longer log with npm run logs:gen)"
        )

    forest_scores = run_isolation_forest(matrix, contamination)
    baseline_scores = score_windows(windows, matrix)
    baseline_raw = np.asarray([score.score for score in baseline_scores])

    # The shared alert budget: both models flag exactly this many windows.
    budget = max(1, math.ceil(contamination * len(windows)))

    forest_flagged = set(np.argsort(-forest_scores)[:budget].tolist())
    baseline_flagged = set(np.argsort(-baseline_raw)[:budget].tolist())

    forest_percentile = rank_percentile(forest_scores)
    baseline_percentile = rank_percentile(baseline_raw)

    anomalies: list[dict[str, Any]] = []

    # The union: a window flagged by either model is reported, tagged with which
    # ones flagged it. Reporting only the intersection would hide exactly the
    # disagreements the comparison exists to surface.
    for index in sorted(forest_flagged | baseline_flagged):
        window = windows[index]
        flagged_by = []
        if index in forest_flagged:
            flagged_by.append("isolation_forest")
        if index in baseline_flagged:
            flagged_by.append("baseline")

        start = datetime.fromisoformat(window.hour_start.replace("Z", "+00:00"))
        end = start + timedelta(hours=WINDOW_HOURS)

        anomalies.append(
            {
                "principalArn": window.principal_arn,
                "windowStart": window.hour_start,
                "windowEnd": end.astimezone(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "eventCount": window.event_count,
                "flaggedBy": flagged_by,
                "scores": {
                    "isolationForest": round(float(forest_percentile[index]), 2),
                    "baseline": round(float(baseline_percentile[index]), 2),
                },
                "rawScores": {
                    "isolationForest": round(float(forest_scores[index]), 6),
                    "baseline": round(float(baseline_raw[index]), 4),
                },
                "evidence": build_evidence(baseline_scores[index]),
                "sampleActions": window.sample_actions,
                "features": {
                    name: round(window.features[name], 4) for name in FEATURE_NAMES
                },
                "eventIds": window.event_ids,
            }
        )

    # Most interesting first, by the primary model.
    anomalies.sort(key=lambda item: -item["scores"]["isolationForest"])

    return {
        "models": {
            "isolationForest": {
                "algorithm": "sklearn.ensemble.IsolationForest",
                "nEstimators": N_ESTIMATORS,
                "randomState": RANDOM_STATE,
                "contamination": contamination,
                "flagged": len(forest_flagged),
            },
            "baseline": {
                "algorithm": "per-principal robust z-score (median/MAD), max over features",
                "flagged": len(baseline_flagged),
            },
        },
        "primaryModel": "isolation_forest",
        "budget": budget,
        "windowCount": len(windows),
        "featureNames": list(FEATURE_NAMES),
        "anomalies": anomalies,
    }


# =============================================================================
# CLI
# =============================================================================


def _print_report(result: dict[str, Any]) -> None:
    """Prints the detections in a readable form."""
    anomalies = result["anomalies"]
    both = sum(1 for a in anomalies if len(a["flaggedBy"]) == 2)

    print(
        f"\n{result['windowCount']:,} windows scored | "
        f"budget {result['budget']} alerts per model | "
        f"{len(anomalies)} distinct windows flagged "
        f"({both} by both models)\n"
    )

    for anomaly in anomalies:
        name = anomaly["principalArn"].split("/")[-1]
        tags = "+".join(
            {"isolation_forest": "IF", "baseline": "Z"}[model]
            for model in anomaly["flaggedBy"]
        )
        when = anomaly["windowStart"].replace("T", " ").replace(":00.000Z", "")
        print(
            f"  [{tags:<5}] {name:<30} {when}  "
            f"{anomaly['eventCount']:>4} events  "
            f"IF {anomaly['scores']['isolationForest']:>6.2f}  "
            f"Z {anomaly['rawScores']['baseline']:>7.1f}"
        )
        for item in anomaly["evidence"]:
            print(f"           - {item['feature']} z={item['zScore']}: {item['description']}")

    print()


def main() -> None:
    """Entry point for ``npm run ml:detect``."""
    parser = argparse.ArgumentParser(
        description="Detect behavioural anomalies in a CloudSentinel activity log."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("fixtures/cloudtrail.json"),
        help="activity log to analyse (default: fixtures/cloudtrail.json)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("fixtures/anomalies.json"),
        help="where to write detections (default: fixtures/anomalies.json)",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=DEFAULT_CONTAMINATION,
        help=(
            "share of windows each model may flag — an alert-capacity choice, "
            f"not an attack-rate estimate (default: {DEFAULT_CONTAMINATION})"
        ),
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="write the output file without printing the report",
    )
    args = parser.parse_args()

    if not 0.0 < args.contamination < 0.5:
        sys.exit(
            f"--contamination must be between 0 and 0.5 (got {args.contamination})"
        )

    events, metadata = load_events(args.input)
    windows = extract_windows(events)
    matrix = to_matrix(windows)

    result = detect(windows, matrix, args.contamination)

    # Carry the source log's provenance through, so a detections file can always
    # be traced back to the exact log — and therefore the exact seed — that
    # produced it. Without this, comparing two detection runs would rely on
    # remembering which log each came from.
    result["source"] = {
        "input": str(args.input),
        "seed": metadata.get("seed"),
        "days": metadata.get("days"),
        "eventCount": len(events),
    }

    if not args.quiet:
        _print_report(result)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out} ({len(result['anomalies'])} flagged windows)\n")


if __name__ == "__main__":
    main()
