"""Confidence scoring for deterministic findings — pure-Python, no LLM.

The analytics engine already produces hard signals: a Jaccard overlap for each
cascade link, a z-score for each error spike, a concentration ratio for each
burst. What it lacked was a single, comparable *confidence* in each conclusion.

This module turns those raw signals into calibrated 0–1 confidences with a plain,
inspectable formula (a logistic squash of a weighted signal blend). The point is
honesty: the report — and the LLM grounded on it — can say "trigger: db (conf
0.86)" instead of stating every inference with equal, unearned certainty.

Everything here is deterministic and dependency-free.
"""

from __future__ import annotations

import math

# Tuning constants. Chosen so a "textbook" signal lands around 0.8–0.9 and a
# marginal one around 0.5; they are deliberately simple, not learned weights.
_LINK_JACCARD_W = 4.0
_LINK_LAG_W = 1.5
_LINK_SEVERITY_W = 0.6
_ONSET_Z_W = 0.9
_ONSET_SUSTAIN_W = 0.5
_TRIGGER_ROOT_BONUS = 1.2
_TRIGGER_EFFECT_W = 0.5
_BURST_CONC_W = 4.0
_BURST_VOLUME_W = 0.4


def logistic(x: float) -> float:
    """Numerically-stable standard logistic squash into (0, 1)."""

    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    z = math.exp(x)
    return z / (1.0 + z)


def link_confidence(
    jaccard: float,
    lag_seconds: float,
    max_lag_seconds: float,
    severity_ordered: bool,
) -> float:
    """Confidence that one cluster *caused* another.

    Stronger when the two overlap heavily in time (``jaccard``), fire close
    together (small ``lag`` relative to the allowed window), and the cause is at
    least as severe as the effect (``severity_ordered``).
    """

    lag_closeness = 1.0 - min(max(lag_seconds, 0.0) / max_lag_seconds, 1.0)
    signal = (
        _LINK_JACCARD_W * jaccard
        + _LINK_LAG_W * lag_closeness
        + (_LINK_SEVERITY_W if severity_ordered else -_LINK_SEVERITY_W)
        - 2.5  # bias so a weak link sits below 0.5
    )
    return round(logistic(signal), 3)


def onset_confidence(zscore: float, n_spikes: int) -> float:
    """Confidence that the detected onset is a real incident start.

    A sharper first spike (higher ``zscore``) and corroborating later spikes
    (``n_spikes``) both raise confidence. An infinite z (a spike against a
    zero-variance baseline) is treated as very strong but not certain.
    """

    z = 6.0 if math.isinf(zscore) else max(zscore, 0.0)
    signal = _ONSET_Z_W * (z - 2.5) + _ONSET_SUSTAIN_W * max(n_spikes - 1, 0)
    return round(logistic(signal), 3)


def trigger_confidence(is_root: bool, n_effects: int, severity_rank: float) -> float:
    """Confidence that the chosen trigger is the true root of the cascade.

    Highest when the trigger is a cause-but-never-effect (a real root), drives
    several downstream failures, and is itself high-severity.
    """

    signal = (
        (_TRIGGER_ROOT_BONUS if is_root else -0.5)
        + _TRIGGER_EFFECT_W * n_effects
        + 0.3 * severity_rank
        - 1.0
    )
    return round(logistic(signal), 3)


def burst_confidence(concentration: float, count: int) -> float:
    """Confidence that a cluster is a genuine burst rather than noise.

    Driven by how concentrated the events are and how many there are (a 90%
    concentration of 200 events is far more telling than of 4).
    """

    volume = math.log1p(max(count, 0))
    signal = _BURST_CONC_W * (concentration - 0.6) + _BURST_VOLUME_W * volume - 0.5
    return round(logistic(signal), 3)


def confidence_label(confidence: float) -> str:
    """A short human label for a confidence value."""

    if confidence >= 0.8:
        return "high"
    if confidence >= 0.55:
        return "moderate"
    if confidence >= 0.35:
        return "low"
    return "tentative"
