"""Tests for the dashboard incident simulator."""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

from loglens.parser import Severity, parse_line
from loglens.web.simulator import Simulator, format_line, incident_script


def test_incident_script_has_clusters_and_severities():
    script = incident_script()
    levels = {lvl for lvl, _, _ in script}
    assert {"INFO", "ERROR", "CRITICAL", "WARNING"} <= levels
    # Repeated DB timeouts form a cluster (the trigger).
    db = [m for _, m, _ in script if "[db]" in m]
    assert len(db) >= 5
    # Every line carries a positive delay.
    assert all(d > 0 for _, _, d in script)


def test_format_line_parses_back():
    line = format_line("ERROR", "[db] boom", datetime(2026, 6, 14, 9, 3, 14))
    entry = parse_line(1, line, "text")
    assert entry.level is Severity.ERROR
    assert entry.timestamp is not None


def test_simulator_writes_then_stops(tmp_path: Path):
    target = tmp_path / "_sim.log"
    sim = Simulator(target)
    sim.start(speed=20.0)
    assert sim.running
    time.sleep(0.6)  # long enough to clear the 6-line healthy preamble
    sim.stop()
    time.sleep(0.1)
    assert target.exists()
    content = target.read_text(encoding="utf-8")
    assert "[api]" in content  # preamble written
    assert "ERROR" in content  # reached the incident
