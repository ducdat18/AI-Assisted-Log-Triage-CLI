"""Tests for CUSUM change-point and seasonal baseline scoring (1b)."""

from __future__ import annotations

from datetime import datetime, timedelta

from loglens.anomaly import (
    bucketize,
    cusum_onset,
    detect_anomalies,
    learn_baseline,
)
from loglens.parser import LogEntry, Severity


def _entry(line_no: int, second: int, level: Severity, msg: str = "boom") -> LogEntry:
    return LogEntry(
        line_no=line_no,
        raw=msg,
        message=msg,
        level=level,
        timestamp=datetime(2026, 1, 1, 0, 0, 0) + timedelta(seconds=second),
    )


def test_cusum_detects_sustained_shift():
    # A long, low steady baseline, then a shorter sustained higher rate (a step,
    # not a one-bucket spike). The baseline stays the majority so the median —
    # and thus the CUSUM reference level — reflects the quiet period.
    entries = [_entry(i, i, Severity.ERROR) for i in range(60)]  # 1/s baseline, 60s
    entries += [_entry(1000 + i, 60 + i // 4, Severity.ERROR) for i in range(80)]  # ~4/s
    buckets = bucketize(entries, bucket_seconds=2)
    series = [b.errors for b in buckets]
    onset = cusum_onset(buckets, series)
    assert onset is not None
    assert onset >= datetime(2026, 1, 1, 0, 1, 0)


def test_cusum_quiet_series_returns_none():
    entries = [_entry(i, i, Severity.ERROR) for i in range(20)]  # flat 1/s
    buckets = bucketize(entries, bucket_seconds=2)
    series = [b.errors for b in buckets]
    assert cusum_onset(buckets, series) is None


def test_learn_baseline_groups_by_hour():
    # Hour 3 has 2 errors/min; hour 4 has 0.
    entries = [_entry(i, 3 * 3600 + i, Severity.ERROR) for i in range(4)]
    entries += [_entry(100 + i, 4 * 3600 + i, Severity.INFO) for i in range(4)]
    model = learn_baseline(entries, bucket_seconds=60)
    assert model.by_hour.get(3, 0) > model.by_hour.get(4, 0)
    assert model.expected(datetime(2026, 1, 1, 3, 0, 0)) > 0


def test_detect_with_baseline_scores_against_expectation():
    # Incident at hour 12 where the healthy baseline expects zero errors.
    incident = [_entry(i, 12 * 3600 + i, Severity.ERROR) for i in range(30)]
    healthy = [_entry(i, 12 * 3600 + i, Severity.INFO) for i in range(30)]
    model = learn_baseline(healthy, bucket_seconds=5)
    report = detect_anomalies(incident, bucket_seconds=5, baseline=model)
    assert report.onset is not None
    assert report.onset_confidence > 0.0
