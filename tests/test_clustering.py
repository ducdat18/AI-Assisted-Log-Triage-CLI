"""Tests for message normalization, clustering, and ranking."""

from __future__ import annotations

from loglens.clustering import (
    cluster_and_rank,
    cluster_entries,
    normalize,
    rank_clusters,
)
from loglens.parser import LogEntry, Severity


def _entry(line_no: int, message: str, level: Severity) -> LogEntry:
    return LogEntry(line_no=line_no, raw=message, message=message, level=level)


def test_normalize_masks_ip_and_numbers():
    a = normalize("Connection to 10.0.4.21:5432 failed after 5000ms")
    b = normalize("Connection to 10.0.4.99:5432 failed after 3000ms")
    assert a == b
    assert "<IP>" in a
    assert "<NUM>" in a


def test_normalize_masks_uuid_and_quotes():
    template = normalize('user 550e8400-e29b-41d4-a716-446655440000 said "hi there"')
    assert "<UUID>" in template
    assert "<STR>" in template


def test_cluster_groups_similar_messages():
    entries = [
        _entry(1, "Connection to 10.0.4.21:5432 failed after 5000ms", Severity.ERROR),
        _entry(2, "Connection to 10.0.4.22:5432 failed after 4000ms", Severity.ERROR),
        _entry(3, "Connection to 10.0.4.23:5432 failed after 6000ms", Severity.ERROR),
    ]
    clusters = cluster_entries(entries, min_level=Severity.WARNING)
    assert len(clusters) == 1
    assert clusters[0].count == 3
    assert clusters[0].representative.line_no == 1


def test_cluster_min_level_filter():
    entries = [
        _entry(1, "all good", Severity.INFO),
        _entry(2, "heads up", Severity.WARNING),
        _entry(3, "boom", Severity.ERROR),
    ]
    clusters = cluster_entries(entries, min_level=Severity.WARNING)
    levels = {c.level for c in clusters}
    assert Severity.INFO not in levels
    assert Severity.WARNING in levels
    assert Severity.ERROR in levels


def test_cluster_min_level_none_includes_everything():
    entries = [_entry(1, "all good", Severity.INFO)]
    clusters = cluster_entries(entries, min_level=None)
    assert len(clusters) == 1


def test_ranking_prioritizes_severity_over_volume():
    entries = [_entry(i, "noisy warning happened", Severity.WARNING) for i in range(50)]
    entries.append(_entry(99, "catastrophic meltdown", Severity.CRITICAL))
    ranked = cluster_and_rank(entries, min_level=Severity.WARNING)
    assert ranked[0].level is Severity.CRITICAL


def test_ranking_rewards_frequency_within_same_level():
    entries = [_entry(i, "frequent error alpha", Severity.ERROR) for i in range(10)]
    entries.append(_entry(99, "rare error beta", Severity.ERROR))
    ranked = rank_clusters(cluster_entries(entries))
    assert ranked[0].count == 10
    assert "alpha" in ranked[0].representative.message


def test_cluster_and_rank_top_n():
    # Distinct *alphabetic* signatures so normalization keeps them separate
    # (numeric ids would be masked and collapse into one cluster).
    entries = [
        _entry(i, f"distinct error category {chr(97 + i)} encountered", Severity.ERROR)
        for i in range(10)
    ]
    ranked = cluster_and_rank(entries, top_n=3)
    assert len(ranked) == 3


def test_cluster_first_and_last_seen_none_without_timestamps():
    entries = [_entry(1, "no timestamp error", Severity.ERROR)]
    cluster = cluster_entries(entries)[0]
    assert cluster.first_seen is None
    assert cluster.last_seen is None
