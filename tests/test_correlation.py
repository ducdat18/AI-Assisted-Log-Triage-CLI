"""Tests for cross-cluster correlation and cascade reconstruction."""

from __future__ import annotations

from datetime import datetime, timedelta

from loglens.clustering import Cluster
from loglens.correlation import correlate_clusters
from loglens.parser import LogEntry, Severity

_BASE = datetime(2026, 1, 1, 0, 0, 0)


def _cluster(template: str, level: Severity, seconds: list[int]) -> Cluster:
    entries = [
        LogEntry(
            line_no=i,
            raw=template,
            message=template,
            level=level,
            timestamp=_BASE + timedelta(seconds=s),
        )
        for i, s in enumerate(seconds)
    ]
    return Cluster(template=template, level=level, entries=entries)


def test_timeline_ordered_by_first_seen():
    later = _cluster("[b] effect", Severity.ERROR, [20, 25])
    earlier = _cluster("[a] cause", Severity.ERROR, [0, 5])
    report = correlate_clusters([later, earlier], bucket_seconds=10)
    assert [e.component for e in report.timeline] == ["a", "b"]


def test_cascade_links_cause_before_effect():
    cause = _cluster("[db] down", Severity.CRITICAL, [0, 5, 10])
    effect = _cluster("[persistence] failed", Severity.ERROR, [2, 7, 12])
    report = correlate_clusters([cause, effect], bucket_seconds=10)
    assert report.has_cascade
    link = report.links[0]
    assert report.timeline[link.cause].component == "db"
    assert report.timeline[link.effect].component == "persistence"
    assert link.lag_seconds > 0


def test_trigger_is_earliest_root_cause():
    cause = _cluster("[db] down", Severity.CRITICAL, [0, 5, 10])
    effect = _cluster("[persistence] failed", Severity.ERROR, [2, 7, 12])
    report = correlate_clusters([effect, cause], bucket_seconds=10)
    assert report.trigger is not None
    assert report.timeline[report.trigger].component == "db"


def test_uncorrelated_clusters_produce_no_links():
    a = _cluster("[a] x", Severity.ERROR, [0])
    b = _cluster("[b] y", Severity.ERROR, [5000])  # far apart -> beyond max lag
    report = correlate_clusters([a, b], bucket_seconds=10)
    assert not report.has_cascade


def test_empty_input_is_safe():
    report = correlate_clusters([], bucket_seconds=10)
    assert report.timeline == ()
    assert report.trigger is None
