r"""CloudSentinel — detector evaluation.

Compares what the detectors flagged against what was actually injected, and
reports precision, recall and per-scenario rank for both models side by side.

    npm run ml:evaluate
    npm run ml:evaluate -- --labels fixtures/cloudtrail-labels.json

Where it sits in the architecture: the last stage of the ML layer, and the only
module in the whole project that is allowed to open the answer key.

    detect.py --> fixtures/anomalies.json ---\
                                              >--> [ this file: evaluate.py ]
    logs:gen --> fixtures/cloudtrail-labels.json /

===============================================================================
Why this file is separate, and why it runs last
===============================================================================

The labels are the answer key. ``features.py``, ``baseline.py`` and
``detect.py`` never read them — not through a flag, not through an import, not
at all. Detection is unsupervised: the models are shown unlabelled activity and
must decide what looks strange without being told. If any of them could see the
labels, they could learn to predict them, and the accuracy figure would measure
nothing except that the answers had been left in the exam room.

Keeping the answer key in a different file, opened by a different module, after
detection has already written its output, is a structural guarantee of that
rather than a promise. It is the reason ``npm run logs:gen`` writes two files.

===============================================================================
How a detection is matched to an attack
===============================================================================

By **event id intersection**, not by timestamp. A detection covers one principal
for one hour and names the specific event ids in that window; a label names the
event ids the injected attack consisted of. If those sets overlap, the detection
found that attack.

Matching on time ranges instead would be sloppy in a way that flatters the
result: an attack starting at 03:20 falls in the 03:00 window, and any alert on
that principal anywhere near that hour would count as a hit even if it fired for
an unrelated reason. Event ids make the match exact.

===============================================================================
How to read the numbers — and how not to
===============================================================================

**Recall** here is per-scenario: of the five injected attacks, how many did the
model surface at all? This is the number that matters most for a security tool.
A missed intrusion is invisible; a false alarm merely costs someone ten minutes.

**Precision** is reported but should be read carefully, because on this dataset
it is bounded well below 1 for a reason that has nothing to do with model
quality. Each model spends a fixed budget of twenty alerts, and there are only
five attacks spanning a handful of windows. Even a perfect detector must fill
its remaining fifteen slots with *something*, and those slots are counted as
false positives. A low precision here means "the budget is larger than the
number of attacks", not "the model is wrong".

The number that does deserve attention is the **control false-positive count**:
how often the two deliberately-difficult-but-innocent principals were flagged.
``cloudsentinel-backup-service`` runs at 3am and makes hundreds of calls an
hour; ``dave-admin`` performs sensitive IAM writes daily. Both are legitimate.
A detector that reports them repeatedly is one an operator will mute within a
week, at which point its recall on real attacks becomes zero regardless of what
this table says.

**The caveat that must travel with any figure from this file**: the evaluation
data is synthetic and was produced by rules this project wrote. A model
evaluated on it is being tested partly against the generator's own assumptions.
These numbers demonstrate that the pipeline works end to end; they are not a
claim about how the detector would perform on a real AWS account, and quoting
them as one would be dishonest. The evaluation prints this caveat itself so it
cannot be separated from the result.

SECURITY: reads two local JSON files, writes nothing, makes no network calls.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Sequence

# =============================================================================
# Constants
# =============================================================================

#: Principals that are difficult but entirely legitimate.
#:
#: Defined in ``lib/logs/generator.ts`` and marked CONTROL there. Any alert on
#: these is a false positive by construction, and they are the cases that decide
#: whether an operator keeps the tool switched on.
CONTROL_PRINCIPALS = (
    "cloudsentinel-backup-service",
    "dave-admin",
)

#: Model keys as they appear in the detections file.
MODELS = ("isolation_forest", "baseline")

#: Display names for those models.
MODEL_LABELS = {
    "isolation_forest": "Isolation Forest",
    "baseline": "Statistical baseline",
}


# =============================================================================
# Loading
# =============================================================================


def load_json(path: Path, what: str, fix: str) -> dict[str, Any]:
    """Reads a JSON file, exiting with an actionable message if it is missing.

    Args:
        path: the file to read.
        what: what the file is, for the error message.
        fix: the command that produces it.

    Returns:
        The parsed document.

    Raises:
        SystemExit: if the file does not exist. A traceback would bury the one
            thing the reader needs, which is the command to run.
    """
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        sys.exit(f"No {what} at {path}.\nCreate it first:  {fix}")


# =============================================================================
# Matching
# =============================================================================


def evaluate_model(
    model: str,
    anomalies: Sequence[dict[str, Any]],
    labels: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    """Scores one model against the answer key.

    Args:
        model: which model's flags to consider, from :data:`MODELS`.
        anomalies: every flagged window, each tagged with the models that
            flagged it.
        labels: the injected attacks.

    Returns:
        A summary containing the alert count, how many alerts matched an attack,
        which scenarios were found and at what rank, and how many alerts landed
        on a control principal.
    """
    # Only this model's alerts, in its own ranking order. The detections file is
    # sorted by the Isolation Forest's score, so the baseline's ranking has to be
    # recovered from its own score rather than from file order — otherwise the
    # "rank" column would silently report the wrong model's ordering.
    flagged = [a for a in anomalies if model in a["flaggedBy"]]
    score_key = "isolationForest" if model == "isolation_forest" else "baseline"
    flagged.sort(key=lambda a: -a["rawScores"][score_key])

    label_events = {
        label["scenario"]: set(label["eventIds"]) for label in labels
    }

    found: dict[str, int] = {}
    true_positives = 0
    control_hits = 0
    # Which principal each false alert landed on, to measure alert fatigue.
    false_alert_sources: Counter[str] = Counter()

    for rank, alert in enumerate(flagged, start=1):
        alert_events = set(alert["eventIds"])
        matched = False

        for scenario, events in label_events.items():
            if alert_events & events:
                matched = True
                # Record the *best* (earliest) rank at which this scenario was
                # surfaced. An analyst working down a list from the top finds it
                # here; later duplicate hits on the same attack add nothing.
                found.setdefault(scenario, rank)

        if matched:
            true_positives += 1
        else:
            false_alert_sources[alert["principalArn"].split("/")[-1]] += 1
            if any(name in alert["principalArn"] for name in CONTROL_PRINCIPALS):
                control_hits += 1

    return {
        "model": model,
        "alerts": len(flagged),
        "truePositives": true_positives,
        "falsePositives": len(flagged) - true_positives,
        "controlFalsePositives": control_hits,
        "scenariosFound": found,
        "recall": len(found) / len(labels) if labels else 0.0,
        "precision": true_positives / len(flagged) if flagged else 0.0,
        # Alert-fatigue measures. The single most repeated false alert source is
        # the number that predicts whether a human keeps reading the alerts: a
        # detector that reports the same cron job twelve times in a month gets
        # muted, and a muted detector has a real-world recall of zero no matter
        # what its recall column says.
        "falseAlertSources": dict(false_alert_sources),
        "worstRepeat": (
            false_alert_sources.most_common(1)[0]
            if false_alert_sources
            else ("none", 0)
        ),
    }


# =============================================================================
# Reporting
# =============================================================================


def print_report(
    detections: dict[str, Any],
    labels: Sequence[dict[str, Any]],
    results: dict[str, dict[str, Any]],
) -> None:
    """Prints the comparison table and the caveats that belong with it."""
    source = detections.get("source", {})

    print(f"\n{'=' * 78}")
    print("  CloudSentinel - anomaly detector evaluation")
    print(f"{'=' * 78}")
    print(
        f"\n  {source.get('eventCount', 0):,} events, "
        f"{detections['windowCount']:,} windows, "
        f"seed {source.get('seed', '?')}, {source.get('days', '?')} days"
    )
    print(
        f"  {len(labels)} injected attacks | "
        f"alert budget {detections['budget']} windows per model\n"
    )

    # --- Headline table ----------------------------------------------------

    print(f"  {'model':<24} {'recall':>8} {'found':>8} {'precision':>10} "
          f"{'alerts':>8} {'control FP':>12}")
    print(f"  {'-' * 24} {'-' * 8} {'-' * 8} {'-' * 10} {'-' * 8} {'-' * 12}")

    for model in MODELS:
        r = results[model]
        print(
            f"  {MODEL_LABELS[model]:<24} "
            f"{r['recall'] * 100:>7.0f}% "
            f"{len(r['scenariosFound'])}/{len(labels):<6} "
            f"{r['precision'] * 100:>9.0f}% "
            f"{r['alerts']:>8} "
            f"{r['controlFalsePositives']:>12}"
        )

    # --- Per-scenario ------------------------------------------------------

    print(f"\n\n  Per scenario - the rank at which each attack was surfaced")
    print("  (lower is better; an analyst reads the list from the top)\n")

    print(f"  {'scenario':<24} {'Isolation Forest':>20} {'Statistical baseline':>22}")
    print(f"  {'-' * 24} {'-' * 20} {'-' * 22}")

    for label in labels:
        scenario = label["scenario"]
        cells = []
        for model in MODELS:
            rank = results[model]["scenariosFound"].get(scenario)
            cells.append(f"#{rank}" if rank else "MISSED")
        print(f"  {scenario:<24} {cells[0]:>20} {cells[1]:>22}")

    # --- Missed attacks ----------------------------------------------------

    for model in MODELS:
        missed = [
            label
            for label in labels
            if label["scenario"] not in results[model]["scenariosFound"]
        ]
        if missed:
            print(f"\n  {MODEL_LABELS[model]} missed:")
            for label in missed:
                print(f"    - {label['scenario']}: {label['description']}")

    # --- Controls ----------------------------------------------------------

    print("\n\n  Control principals (legitimate but deliberately difficult)")
    print("  A detector that repeatedly flags these gets muted, and a muted")
    print("  detector has a real-world recall of zero.\n")

    for model in MODELS:
        count = results[model]["controlFalsePositives"]
        verdict = "clean" if count == 0 else f"{count} false alerts"
        print(f"    {MODEL_LABELS[model]:<24} {verdict}")

    print("\n\n  Alert fatigue - how repetitive is each model's false-alert stream?")
    print("  A model that reports the same benign job every night trains its")
    print("  reader to ignore it, and the recall column above then means nothing.\n")

    for model in MODELS:
        r = results[model]
        source, count = r["worstRepeat"]
        share = count / r["alerts"] if r["alerts"] else 0.0
        print(
            f"    {MODEL_LABELS[model]:<24} "
            f"most repeated: {source} x{count} "
            f"({share:.0%} of its budget)"
        )

    # --- Caveat ------------------------------------------------------------

    print(f"\n{'=' * 78}")
    print("  HOW TO READ THIS")
    print(f"{'=' * 78}")
    print(
        "\n  Precision is bounded well below 100% by construction: each model\n"
        "  spends a fixed budget of alerts, and there are far fewer attacks\n"
        "  than budget slots. Unmatched alerts are 'unexplained but benign',\n"
        "  not 'wrong'. Recall and the control false-positive count are the\n"
        "  numbers that carry real information.\n"
    )
    print(
        "  These figures come from SYNTHETIC data generated by this project's\n"
        "  own rules, so the models are partly being tested against the\n"
        "  generator's assumptions. They demonstrate that the pipeline works\n"
        "  end to end. They are NOT a claim about accuracy on a real AWS\n"
        "  account, and should never be quoted as one.\n"
    )


# =============================================================================
# CLI
# =============================================================================


def main() -> None:
    """Entry point for ``npm run ml:evaluate``."""
    parser = argparse.ArgumentParser(
        description="Evaluate CloudSentinel's anomaly detectors against ground truth."
    )
    parser.add_argument(
        "--detections",
        type=Path,
        default=Path("fixtures/anomalies.json"),
        help="detections file (default: fixtures/anomalies.json)",
    )
    parser.add_argument(
        "--labels",
        type=Path,
        default=Path("fixtures/cloudtrail-labels.json"),
        help="ground-truth labels (default: fixtures/cloudtrail-labels.json)",
    )
    parser.add_argument(
        "--require-recall",
        type=float,
        default=None,
        help=(
            "exit non-zero if the primary model's recall falls below this "
            "fraction — used by CI to catch a regression in the pipeline"
        ),
    )
    args = parser.parse_args()

    detections = load_json(args.detections, "detections file", "npm run ml:detect")
    label_doc = load_json(args.labels, "labels file", "npm run logs:gen")
    labels = label_doc["labels"]

    if not labels:
        sys.exit(
            "The labels file contains no attacks, so there is nothing to "
            "evaluate against.\nThis is expected after `npm run logs:gen -- "
            "--no-attacks`, which measures false positives instead."
        )

    results = {
        model: evaluate_model(model, detections["anomalies"], labels)
        for model in MODELS
    }

    print_report(detections, labels, results)

    if args.require_recall is not None:
        primary = results["isolation_forest"]
        if primary["recall"] < args.require_recall:
            sys.exit(
                f"FAIL: Isolation Forest recall {primary['recall']:.0%} is below "
                f"the required {args.require_recall:.0%}"
            )
        print(
            f"  Recall gate passed: {primary['recall']:.0%} "
            f">= {args.require_recall:.0%}\n"
        )


if __name__ == "__main__":
    main()
