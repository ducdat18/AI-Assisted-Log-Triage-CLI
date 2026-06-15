"""Tests for the Loki exporter (HTTP mocked)."""

from __future__ import annotations

from datetime import datetime

import pytest

from loglens.exporters import loki
from loglens.exporters.loki import LokiClient, LokiError, build_streams, signature
from loglens.parser import LogEntry, Severity


def _entry(line_no: int, message: str, level: Severity, ts: datetime | None = None) -> LogEntry:
    return LogEntry(line_no=line_no, raw=message, message=message, level=level, timestamp=ts)


def test_signature_stable_across_variable_parts():
    a = signature("Connection to 10.0.4.21:5432 failed after 5000ms")
    b = signature("Connection to 10.0.4.99:5432 failed after 9000ms")
    assert a == b
    assert signature("totally different error") != a


def test_build_streams_groups_by_level_and_cluster():
    entries = [
        _entry(1, "Connection to 10.0.0.1 failed", Severity.ERROR),
        _entry(2, "Connection to 10.0.0.2 failed", Severity.ERROR),
        _entry(3, "Disk almost full at 90%", Severity.WARNING),
    ]
    streams = build_streams(entries, source="test.log")
    # Two error lines collapse into one stream; the warning is its own stream.
    assert len(streams) == 2
    by_level = {s["stream"]["level"]: s for s in streams}
    assert len(by_level["error"]["values"]) == 2
    assert len(by_level["warning"]["values"]) == 1


def test_build_streams_labels_present():
    streams = build_streams([_entry(1, "boom", Severity.ERROR)], source="api.log")
    labels = streams[0]["stream"]
    assert labels["job"] == "loglens"
    assert labels["source"] == "api.log"
    assert labels["level"] == "error"
    assert len(labels["cluster"]) == 10


def test_build_streams_values_sorted_ascending():
    entries = [
        _entry(1, "same kind of error", Severity.ERROR, datetime(2026, 6, 14, 9, 0, 5)),
        _entry(2, "same kind of error", Severity.ERROR, datetime(2026, 6, 14, 9, 0, 1)),
    ]
    streams = build_streams(entries, source="t.log")
    timestamps = [int(v[0]) for v in streams[0]["values"]]
    assert timestamps == sorted(timestamps)


def test_build_streams_redaction_applied():
    entries = [_entry(1, "login failed for admin@corp.com", Severity.ERROR)]
    streams = build_streams(entries, source="t.log", redact=True)
    line = streams[0]["values"][0][1]
    assert "admin@corp.com" not in line
    assert "[REDACTED:EMAIL]" in line


def test_build_streams_unknown_level_label():
    streams = build_streams([_entry(1, "no level here", None)], source="t.log")  # type: ignore[arg-type]
    assert streams[0]["stream"]["level"] == "unknown"


class _FakeResponse:
    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


def test_client_push_success(monkeypatch):
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["json"] = kwargs["json"]
        return _FakeResponse(204)

    monkeypatch.setattr(loki.requests, "post", fake_post)
    client = LokiClient("http://localhost:3100")
    streams = build_streams([_entry(1, "boom", Severity.ERROR)], source="t.log")
    shipped = client.push(streams)

    assert shipped == 1
    assert captured["url"] == "http://localhost:3100/loki/api/v1/push"
    assert "streams" in captured["json"]


def test_client_push_empty_is_noop(monkeypatch):
    def fake_post(*a, **k):  # pragma: no cover - should not be called
        raise AssertionError("push should not hit the network for empty streams")

    monkeypatch.setattr(loki.requests, "post", fake_post)
    assert LokiClient().push([]) == 0


def test_client_push_rejects_error_status(monkeypatch):
    monkeypatch.setattr(loki.requests, "post", lambda *a, **k: _FakeResponse(400, "bad request"))
    client = LokiClient()
    streams = build_streams([_entry(1, "boom", Severity.ERROR)], source="t.log")
    with pytest.raises(LokiError):
        client.push(streams)


def test_client_push_connection_error(monkeypatch):
    def fake_post(*a, **k):
        raise loki.requests.exceptions.ConnectionError("no route")

    monkeypatch.setattr(loki.requests, "post", fake_post)
    with pytest.raises(LokiError) as exc:
        LokiClient().push(build_streams([_entry(1, "boom", Severity.ERROR)], source="t.log"))
    assert "Could not reach Loki" in str(exc.value)
