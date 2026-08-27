r"""CloudSentinel — statistical baseline anomaly detector.

Scores each behavioural window with a robust z-score per feature, then takes the
worst one. No machine learning, no scikit-learn, no training step — just medians
and absolute deviations, in about forty lines of arithmetic.

Where it sits in the architecture: the *control* for the ML layer.

    features.py --> [ this file: baseline.py ] --\
                \                                 >--> evaluate.py
                 -> detect.py (Isolation Forest) -/

===============================================================================
Why a deliberately simple model exists
===============================================================================

This file is the answer to the most important question anyone should ask about
the ML layer: **does the machine learning actually earn its place?**

It is very easy to add scikit-learn to a project, report that the Isolation
Forest found four of five injected attacks, and imply the model is responsible.
Very often a handful of if-statements would have found the same four, and the
model is decoration — an impressive-sounding dependency that adds training time,
a supply-chain surface, and a scoring function nobody can explain to an auditor.

So the pipeline runs both, on identical features, and reports them side by side.
If this file matches the Isolation Forest, that is a genuine and useful result:
it means CloudSentinel should ship the version that has no ML dependency, runs
instantly, and produces a number an analyst can recompute by hand. If the
Isolation Forest wins, the comparison shows precisely where and by how much.
Either way the claim is measured rather than assumed.

The honest expectation, stated in advance so it cannot be quietly revised
afterwards: this baseline should do well on the loud scenarios (the error burst,
the volume spike) because those blow out a single feature, and it should
struggle where an attack is only unusual as a *combination* of individually
unremarkable features — which is exactly the regime an Isolation Forest is
supposed to be good at.

===============================================================================
Why robust statistics rather than mean and standard deviation
===============================================================================

The obvious version of this detector is ``(x - mean) / stddev``. It does not
work here, for a reason worth understanding: the attacks are *in the data being
used to define normal*. A single 322-event exfiltration hour pulls the mean up
and inflates the standard deviation, and the inflated denominator then shrinks
the z-score of the very window that caused it. The anomaly hides itself. This is
sometimes called masking, and it gets worse as the attack gets larger.

Median and MAD do not have that problem. Both have a 50% breakdown point: more
than half the windows would have to be attacks before either moved
meaningfully. Five attack windows out of roughly two thousand cannot shift them
at all, so the yardstick stays honest no matter how extreme the outlier is.

SECURITY: pure arithmetic on a local array. No network, no credentials, no
filesystem access of its own. This module deliberately imports nothing beyond
NumPy and the standard library, so that if scikit-learn were ever unavailable or
untrusted the pipeline would still produce a working detector — see the note in
``requirements.txt``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import numpy as np

from features import FEATURE_DESCRIPTIONS, FEATURE_NAMES, Window

# =============================================================================
# Constants
# =============================================================================

#: Rescales a median absolute deviation to be comparable with a standard
#: deviation for normally distributed data. Standard constant, not a tuned one.
MAD_TO_SIGMA = 1.4826

#: Hard floor on the scale, applied only to features that never vary at all.
#:
#: Reached only when a feature is literally constant across every one of a
#: principal's windows, in which case its deviation is always zero and the
#: z-score is 0/MIN_SCALE = 0. That is the correct answer: a feature that never
#: moves carries no information.
MIN_SCALE = 1e-9

#: How many features are reported as the reason for a detection, and how many
#: are summed to produce the window's score.
TOP_CONTRIBUTORS = 3

#: Ceiling applied to every per-feature z-score before aggregation.
#:
#: Winsorising, and it is needed because several features are near-constant. A
#: principal that has used exactly one source address in every window has a mean
#: absolute deviation close to zero on ``distinct_ips``, so the single window
#: where it used two scored 346 "standard deviations" — a number that says
#: nothing except that the feature almost never moves.
#:
#: Left uncapped, the ranking becomes "which window moved the rarest feature"
#: rather than "which window is most extreme", and one near-binary column
#: silently decides every alert. Anything past 25 robust deviations is already
#: as unusual as the data can express, so capping there loses no information
#: that ranking could use.
Z_CAP = 25.0


# =============================================================================
# Scoring
# =============================================================================


@dataclass
class BaselineScore:
    """One window's baseline result."""

    #: Sum of the three worst per-feature robust z-scores, each capped at Z_CAP.
    score: float

    #: Per-feature z-scores, keyed by feature name.
    per_feature: dict[str, float]

    #: The features that drove the score, worst first, as
    #: ``(name, z_score, plain-language description)``.
    contributors: list[tuple[str, float, str]]


def _robust_scale(column: np.ndarray) -> tuple[float, float]:
    """Computes the median and a robust scale for one feature column.

    The MAD degenerates to exactly zero whenever more than half the windows
    share the same value, which is the *normal* case for most features here:
    most hours contain no sensitive calls, no failures, and no unseen regions,
    so the median and the MAD are both 0. Dividing by that gives infinity, and
    substituting a small constant is worse than it looks — it turns every
    such feature into a switch that returns an enormous score the moment it is
    non-zero, and the model's ranking becomes "which window has any rare feature
    at all" rather than "which window is most extreme".

    So a degenerate MAD falls back to the *mean* absolute deviation from the
    median. That is less robust — a large outlier does inflate it — but it is
    only used when the robust estimator has no signal to work with, and it
    extracts a usable scale from the minority of windows that do vary. The
    result is finite, proportionate, and still centred on the median.

    Args:
        column: every window's value for a single feature.

    Returns:
        A ``(centre, scale)`` pair, with ``scale`` strictly positive.
    """
    centre = float(np.median(column))
    deviations = np.abs(column - centre)

    scale = MAD_TO_SIGMA * float(np.median(deviations))

    if scale <= MIN_SCALE:
        scale = float(np.mean(deviations))

    return centre, max(scale, MIN_SCALE)


def score_windows(
    windows: Sequence[Window], matrix: np.ndarray
) -> list[BaselineScore]:
    """Scores every window by its most extreme feature.

    Scaling is computed *per principal*, not across the whole account. That
    matters as much here as it does in feature extraction: a global scale would
    be dominated by the backup role, which produces more than a third of all
    windows, and every human principal would then be measured against a
    yardstick built from a machine's behaviour.

    Aggregation is the **sum of the three worst features**, each capped at
    :data:`Z_CAP`. Both halves of that were arrived at by watching the first
    version fail, and both are worth understanding.

    The first version took the single worst feature. It does not work, because
    several features here are effectively binary — ``hour_rarity`` is near 0 for
    every in-hours window and near 1 for every out-of-hours one. Every off-hours
    window therefore produced an almost identical score, the whole alert budget
    filled up with ties, and which of the fifteen tied windows got reported was
    decided by array order rather than by anything meaningful.

    Summing the top three breaks those ties with real information: a window that
    is unusual on volume *and* resource count *and* error rate outranks one that
    is unusual only on the hour. Averaging across all fourteen features would go
    too far the other way, dividing a genuine spike by fourteen columns of
    ordinary behaviour.

    The weakness that remains, stated plainly since it is the reason
    ``detect.py`` exists: three features is still a fixed, hand-chosen
    combination rule. An attack that is mildly unusual on eight features at once
    and extreme on none scores no better than one mildly unusual on three. Only
    a model that learns the shape of the whole feature space handles that, which
    is exactly what the Isolation Forest is being tested on.

    Args:
        windows: the windows being scored, aligned row-for-row with ``matrix``.
        matrix: feature values, from :func:`features.to_matrix`.

    Returns:
        One :class:`BaselineScore` per window, in the same order.

    Raises:
        ValueError: if ``windows`` and ``matrix`` disagree in length, which would
            silently attribute one window's score to another.
    """
    if len(windows) != matrix.shape[0]:
        raise ValueError(
            f"windows ({len(windows)}) and matrix ({matrix.shape[0]}) must align"
        )

    # Group row indices by principal, so each principal gets its own yardstick.
    rows_by_principal: dict[str, list[int]] = {}
    for index, window in enumerate(windows):
        rows_by_principal.setdefault(window.principal_arn, []).append(index)

    scores: list[BaselineScore] = [None] * len(windows)  # type: ignore[list-item]

    for rows in rows_by_principal.values():
        block = matrix[rows, :]

        centres_and_scales = [
            _robust_scale(block[:, column]) for column in range(block.shape[1])
        ]

        for local_index, row_index in enumerate(rows):
            per_feature: dict[str, float] = {}

            for column, name in enumerate(FEATURE_NAMES):
                centre, scale = centres_and_scales[column]
                # Absolute deviation: a feature that is unusually *low* is as
                # statistically odd as one that is unusually high. In practice
                # the high side carries nearly all the security signal, but
                # taking the absolute value keeps this a general outlier
                # detector rather than one that quietly encodes assumptions
                # about which direction is bad.
                deviation = abs(float(block[local_index, column]) - centre) / scale
                # Capped before it is ever used, so the cap applies to the
                # reported evidence as well as to the score — an alert claiming
                # "346 standard deviations" would be worse than useless.
                per_feature[name] = min(deviation, Z_CAP)

            ranked = sorted(per_feature.items(), key=lambda item: item[1], reverse=True)

            scores[row_index] = BaselineScore(
                score=sum(value for _, value in ranked[:TOP_CONTRIBUTORS]),
                per_feature=per_feature,
                contributors=[
                    (name, value, FEATURE_DESCRIPTIONS[name])
                    for name, value in ranked[:TOP_CONTRIBUTORS]
                ],
            )

    return scores


def explain(score: BaselineScore) -> str:
    """Renders a baseline score as a one-line human explanation.

    Args:
        score: the score to describe.

    Returns:
        A string such as ``"volume_ratio 22.7 (call volume relative to this
        principal's typical hour); error_excess 3.1 (...)"``.
    """
    return "; ".join(
        f"{name} z={value:.1f} ({description})"
        for name, value, description in score.contributors
        if value > 1.0
    )
