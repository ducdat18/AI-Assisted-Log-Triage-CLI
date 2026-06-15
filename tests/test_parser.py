"""Tests for log format detection and parsing."""

from __future__ import annotations

from datetime import datetime

from loglens.parser import (
    Severity,
    detect_format,
    parse_line,
    parse_lines,
)

TEXT_LINES = [
    "2026-06-14 09:03:14 ERROR [db] Connection to 10.0.4.21:5432 failed",
    "2026-06-14 09:03:15 INFO  [auth] Player connected uid=10241",
    "2026-06-14 09:03:16 WARN  [worldsim] Tick budget exceeded: 18.4ms",
]

JSON_LINES = [
    '{"timestamp": "2026-06-14T11:00:01.120Z", "level": "info", "msg": "Server up"}',
    '{"timestamp": "2026-06-14T11:00:15.220Z", "level": "error", "msg": "502 upstream"}',
]


def test_detect_format_text():
    assert detect_format(TEXT_LINES) == "text"


def test_detect_format_json():
    assert detect_format(JSON_LINES) == "json"


def test_detect_format_empty_defaults_to_text():
    assert detect_format([]) == "text"
    assert detect_format(["", "   ", "\n"]) == "text"


def test_parse_text_line_extracts_level_and_timestamp():
    entry = parse_line(1, TEXT_LINES[0], "text")
    assert entry.level is Severity.ERROR
    assert entry.is_error is True
    assert entry.timestamp == datetime(2026, 6, 14, 9, 3, 14)
    assert "Connection to" in entry.message


def test_parse_text_warn_alias():
    entry = parse_line(3, TEXT_LINES[2], "text")
    assert entry.level is Severity.WARNING
    assert entry.is_error is False


def test_parse_json_line_extracts_fields():
    entry = parse_line(2, JSON_LINES[1], "json")
    assert entry.level is Severity.ERROR
    assert entry.message == "502 upstream"
    assert entry.timestamp is not None
    assert entry.fields["level"] == "error"


def test_parse_json_falls_back_to_text_on_bad_json():
    entry = parse_line(1, "this is not json ERROR boom", "json")
    # Malformed JSON is parsed as text, still recovering the level.
    assert entry.level is Severity.ERROR
    assert "boom" in entry.message


def test_parse_lines_skips_blank_and_auto_detects():
    lines = ["", *JSON_LINES, "   "]
    entries = parse_lines(lines)
    assert len(entries) == 2
    assert all(e.fields for e in entries)


def test_parse_lines_line_numbers_are_sequential():
    entries = parse_lines(TEXT_LINES, fmt="text")
    assert [e.line_no for e in entries] == [1, 2, 3]


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.ERROR > Severity.WARNING > Severity.INFO


def test_severity_from_text_unknown_returns_none():
    assert Severity.from_text("BOGUS") is None
    assert Severity.from_text(None) is None
