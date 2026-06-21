"""Tests for the deterministic confidence-scoring formulas."""

from __future__ import annotations

import math

from loglens.scoring import (
    burst_confidence,
    confidence_label,
    link_confidence,
    logistic,
    onset_confidence,
    trigger_confidence,
)


def test_logistic_range_and_monotonic():
    assert 0.0 < logistic(-10) < logistic(0) < logistic(10) < 1.0
    assert math.isclose(logistic(0), 0.5)


def test_link_confidence_higher_with_overlap_and_low_lag():
    strong = link_confidence(jaccard=0.9, lag_seconds=5, max_lag_seconds=600, severity_ordered=True)
    weak = link_confidence(
        jaccard=0.2, lag_seconds=550, max_lag_seconds=600, severity_ordered=False
    )
    assert strong > weak
    assert 0.0 <= weak <= strong <= 1.0
    assert strong >= 0.8


def test_link_confidence_severity_ordering_helps():
    ordered = link_confidence(0.5, 60, 600, severity_ordered=True)
    reversed_ = link_confidence(0.5, 60, 600, severity_ordered=False)
    assert ordered > reversed_


def test_onset_confidence_handles_inf_and_grows_with_spikes():
    one = onset_confidence(3.0, n_spikes=1)
    many = onset_confidence(3.0, n_spikes=5)
    assert many > one
    inf = onset_confidence(math.inf, n_spikes=1)
    assert 0.0 < inf < 1.0


def test_trigger_confidence_root_beats_nonroot():
    root = trigger_confidence(is_root=True, n_effects=3, severity_rank=1.0)
    nonroot = trigger_confidence(is_root=False, n_effects=0, severity_rank=0.2)
    assert root > nonroot
    assert root >= 0.8


def test_burst_confidence_scales_with_concentration_and_volume():
    big = burst_confidence(concentration=0.95, count=500)
    small = burst_confidence(concentration=0.61, count=4)
    assert big > small
    assert 0.0 <= small <= big <= 1.0


def test_confidence_label_bands():
    assert confidence_label(0.9) == "high"
    assert confidence_label(0.6) == "moderate"
    assert confidence_label(0.4) == "low"
    assert confidence_label(0.1) == "tentative"
