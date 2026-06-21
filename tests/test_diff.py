"""Tests for signature diffing between two logs."""

from __future__ import annotations

from loglens.clustering import Cluster
from loglens.diff import diff_clusters
from loglens.parser import LogEntry, Severity


def _cluster(template: str, level: Severity, n: int) -> Cluster:
    c = Cluster(template=template, level=level)
    c.entries = [LogEntry(line_no=i, raw=template, message=template, level=level) for i in range(n)]
    return c


def test_diff_classifies_changes():
    before = [
        _cluster("db timeout", Severity.ERROR, 2),
        _cluster("slow query", Severity.WARNING, 5),
        _cluster("old bug", Severity.ERROR, 3),
    ]
    after = [
        _cluster("db timeout", Severity.ERROR, 9),  # worsened
        _cluster("slow query", Severity.WARNING, 2),  # improved
        _cluster("new failure", Severity.CRITICAL, 4),  # new
        # "old bug" disappeared -> resolved
    ]
    report = diff_clusters(before, after)
    statuses = {d.template: d.status for d in report.deltas}
    assert statuses["db timeout"] == "worsened"
    assert statuses["slow query"] == "improved"
    assert statuses["new failure"] == "new"
    assert statuses["old bug"] == "resolved"


def test_diff_unchanged():
    before = [_cluster("steady", Severity.WARNING, 4)]
    after = [_cluster("steady", Severity.WARNING, 4)]
    report = diff_clusters(before, after)
    assert report.by_status("unchanged")
    assert report.deltas[0].delta == 0


def test_diff_orders_new_and_worse_first():
    before = [_cluster("x", Severity.WARNING, 4)]
    after = [_cluster("x", Severity.WARNING, 4), _cluster("y", Severity.ERROR, 10)]
    report = diff_clusters(before, after)
    assert report.deltas[0].status == "new"
