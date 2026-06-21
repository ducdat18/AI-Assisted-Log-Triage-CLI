"""Tests for semantic cluster merging (1c)."""

from __future__ import annotations

from loglens.clustering import Cluster
from loglens.parser import LogEntry, Severity
from loglens.semantic import TfidfEmbedder, cosine, merge_similar


def _cluster(template: str, level: Severity, n: int = 1) -> Cluster:
    c = Cluster(template=template, level=level)
    c.entries = [LogEntry(line_no=i, raw=template, message=template, level=level) for i in range(n)]
    return c


def test_tfidf_cosine_high_for_overlapping_text():
    emb = TfidfEmbedder()
    a, b, c = emb.embed(
        [
            "database connection refused timeout",
            "database connection refused timeout again",
            "user logged in successfully",
        ]
    )
    assert cosine(a, b) > cosine(a, c)


def test_merge_similar_folds_near_duplicates():
    clusters = [
        _cluster("database connection failed timeout", Severity.ERROR, n=3),
        _cluster("database connection failed timeout occurred", Severity.ERROR, n=2),
        _cluster("user login succeeded", Severity.INFO, n=1),
    ]
    merged = merge_similar(clusters, threshold=0.5)
    assert len(merged) < len(clusters)
    # The merged DB cluster aggregates entries from both near-duplicates.
    top = merged[0]
    assert top.count == 5


def test_merge_similar_keeps_distinct_apart():
    clusters = [
        _cluster("disk full on volume", Severity.ERROR, n=2),
        _cluster("payment gateway rejected card", Severity.ERROR, n=2),
    ]
    merged = merge_similar(clusters, threshold=0.9)
    assert len(merged) == 2


def test_merge_similar_noop_for_single_cluster():
    clusters = [_cluster("only one", Severity.WARNING)]
    assert merge_similar(clusters) == clusters


def test_merge_preserves_highest_severity():
    clusters = [
        _cluster("shard unresponsive failover triggered", Severity.WARNING, n=5),
        _cluster("shard unresponsive failover triggered now", Severity.CRITICAL, n=1),
    ]
    merged = merge_similar(clusters, threshold=0.5)
    assert len(merged) == 1
    assert merged[0].level == Severity.CRITICAL
