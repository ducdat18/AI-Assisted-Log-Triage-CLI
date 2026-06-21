"""Tests for temporal anomaly detection."""

from __future__ import annotations

from datetime import datetime, timedelta

from loglens.anomaly import bucketize, choose_bucket_seconds, detect_anomalies
from loglens.clustering import cluster_and_rank
from loglens.parser import LogEntry, Severity


def _entry(line_no: int, second: int, level: Severity, msg: str = "boom") -> LogEntry:
    return LogEntry(
        line_no=line_no,
        raw=msg,
        message=msg,
        level=level,
        timestamp=datetime(2026, 1, 1, 0, 0, 0) + timedelta(seconds=second),
    )


def test_choose_bucket_seconds_scales_with_span():
    assert choose_bucket_seconds(10) <= choose_bucket_seconds(100_000)
    assert choose_bucket_seconds(0) >= 1


def test_bucketize_counts_errors_and_warnings():
    entries = [
        _entry(1, 0, Severity.INFO),
        _entry(2, 1, Severity.WARNING),
        _entry(3, 2, Severity.ERROR),
        _entry(4, 3, Severity.CRITICAL),
    ]
    buckets = bucketize(entries, bucket_seconds=10)
    assert len(buckets) == 1
    assert buckets[0].total == 4
    assert buckets[0].errors == 2  # ERROR + CRITICAL
    assert buckets[0].warnings == 1


def test_detect_anomalies_finds_onset_on_error_spike():
    # 30s of quiet INFO, then a sudden burst of errors.
    entries = [_entry(i, i, Severity.INFO) for i in range(30)]
    entries += [_entry(100 + i, 31 + i, Severity.ERROR) for i in range(20)]
    report = detect_anomalies(entries, bucket_seconds=5)
    assert report.onset is not None
    assert report.spikes
    assert report.peak_errors > 0
    # Onset should land at/after the quiet period.
    assert report.onset >= datetime(2026, 1, 1, 0, 0, 30)


def test_no_timestamps_yields_empty_report():
    entries = [LogEntry(line_no=1, raw="x", message="x", level=Severity.ERROR)]
    report = detect_anomalies(entries)
    assert report.onset is None
    assert report.buckets == ()
    assert not report.has_anomalies


def test_burst_detection_flags_concentrated_cluster():
    # 10 identical errors all within 2 seconds = bursty.
    entries = [_entry(i, i % 2, Severity.ERROR, "db pool exhausted") for i in range(10)]
    clusters = cluster_and_rank(entries, min_level=Severity.WARNING)
    report = detect_anomalies(entries, clusters=clusters, bucket_seconds=30)
    assert report.bursts
    assert report.bursts[0].concentration >= 0.6
