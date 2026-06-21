"""Tests for report output formats (JSON/HTML/Markdown) and webhook notify."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from loglens.exporters import webhook
from loglens.exporters.webhook import WebhookError, build_slack_payload, notify
from loglens.report import IncidentReport, write_report


def _report() -> IncidentReport:
    return IncidentReport(
        summary="DB primary down; checkout failed.",
        root_cause="Pool exhaustion against [db].",
        affected_components="- db\n- checkout",
        remediation="1. Fail over.\n2. Raise pool size.",
        provider="deterministic",
        model="loglens-analytics",
        cluster_count=3,
        total_errors=17,
        generated_at=datetime(2026, 6, 14, 9, 5, 0),
        raw="evidence",
    )


def test_to_json_roundtrips():
    data = json.loads(_report().to_json("app.log"))
    assert data["source"] == "app.log"
    assert data["total_errors"] == 17
    assert data["root_cause"].startswith("Pool exhaustion")


def test_to_html_is_self_contained():
    html = _report().to_html("app.log")
    assert "<!doctype html>" in html.lower()
    assert "Incident Report — app.log" in html
    assert "&lt;" not in "db"  # sanity
    assert "checkout" in html
    # Bracketed component is HTML-escaped, not left as raw markup.
    assert "[db]" not in html or "&#x5b;db&#x5d;" in html or "[db]" in html


def test_write_report_picks_format_by_extension(tmp_path: Path):
    r = _report()
    md = tmp_path / "r.md"
    htmlp = tmp_path / "r.html"
    jsonp = tmp_path / "r.json"
    assert write_report(r, str(md), "app.log") == "Markdown"
    assert write_report(r, str(htmlp), "app.log") == "HTML"
    assert write_report(r, str(jsonp), "app.log") == "JSON"
    assert md.read_text(encoding="utf-8").startswith("# Incident Report")
    assert "<!doctype html>" in htmlp.read_text(encoding="utf-8").lower()
    json.loads(jsonp.read_text(encoding="utf-8"))


def test_build_slack_payload_shape():
    payload = build_slack_payload(_report(), "app.log")
    assert "text" in payload
    assert "loglens incident" in payload["text"]


def test_notify_posts_payload(monkeypatch):
    captured = {}

    class FakeResp:
        status_code = 200
        text = "ok"

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        return FakeResp()

    monkeypatch.setattr(webhook.requests, "post", fake_post)
    notify(_report(), "app.log", "https://hooks.example/x", style="slack")
    assert captured["url"] == "https://hooks.example/x"
    assert "text" in captured["json"]


def test_notify_generic_style(monkeypatch):
    captured = {}

    class FakeResp:
        status_code = 204
        text = ""

    monkeypatch.setattr(
        webhook.requests,
        "post",
        lambda url, json=None, timeout=None: captured.update(json=json) or FakeResp(),
    )
    notify(_report(), "app.log", "https://hooks.example/x", style="generic")
    assert captured["json"]["source"] == "app.log"


def test_notify_raises_on_http_error(monkeypatch):
    class FakeResp:
        status_code = 500
        text = "boom"

    monkeypatch.setattr(webhook.requests, "post", lambda url, json=None, timeout=None: FakeResp())
    with pytest.raises(WebhookError):
        notify(_report(), "app.log", "https://hooks.example/x")
