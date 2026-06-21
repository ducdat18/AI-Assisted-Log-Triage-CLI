"""Tests for the incident analytics layer (deterministic report + evidence)."""

from __future__ import annotations

from rich.console import Console

from loglens.clustering import cluster_and_rank
from loglens.incident import (
    analyze_incident,
    deterministic_report,
    evidence_block,
    render_findings,
)
from loglens.parser import Severity, parse_file


def _findings_for(path: str):
    entries = parse_file(path)
    clusters = cluster_and_rank(entries, top_n=8, min_level=Severity.WARNING)
    return entries, clusters, analyze_incident(entries, clusters)


def test_analyze_incident_on_game_server_finds_db_trigger():
    entries, clusters, findings = _findings_for("sample_logs/game_server.log")
    assert findings.anomaly.onset is not None
    trig = findings.correlation.timeline[findings.correlation.trigger]
    assert trig.component == "db"
    assert findings.correlation.has_cascade


def test_evidence_block_mentions_onset_and_cascade():
    _, _, findings = _findings_for("sample_logs/game_server.log")
    block = evidence_block(findings)
    assert "onset" in block.lower()
    assert "cascade" in block.lower()
    assert "COMPUTED EVIDENCE" in block


def test_deterministic_report_is_complete_without_llm():
    _, clusters, findings = _findings_for("sample_logs/game_server.log")
    report = deterministic_report(findings, clusters, source="game_server.log")
    assert report.provider == "deterministic"
    assert report.summary
    assert "db" in report.root_cause
    assert report.affected_components
    assert report.remediation
    md = report.to_markdown("game_server.log")
    assert "# Incident Report" in md
    assert "Remediation" in md


def test_deterministic_report_json_source():
    _, clusters, findings = _findings_for("sample_logs/api_server.jsonl")
    report = deterministic_report(findings, clusters, source="api_server.jsonl")
    # JSON logs carry a 'service' field — components should be named, not '?'.
    assert "payments-svc" in report.affected_components or "checkout" in report.affected_components


def test_render_findings_emits_timeline_and_cascade():
    _, _, findings = _findings_for("sample_logs/game_server.log")
    console = Console(record=True, width=120)
    render_findings(findings, console)
    text = console.export_text()
    assert "Incident timeline" in text
    assert "Inferred cascade" in text
    assert "db" in text


def test_render_findings_handles_no_timestamps():
    from loglens.parser import LogEntry

    entries = [LogEntry(line_no=1, raw="x", message="x", level=Severity.ERROR)]
    clusters = cluster_and_rank(entries, min_level=Severity.WARNING)
    findings = analyze_incident(entries, clusters)
    console = Console(record=True, width=120)
    render_findings(findings, console)  # must not raise on empty timeline
