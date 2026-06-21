"""Tests for extended ingestion: syslog, logfmt, CLF, multiline, gzip, sources."""

from __future__ import annotations

import gzip
from pathlib import Path

from loglens.parser import (
    Severity,
    detect_format,
    parse_file,
    parse_line,
    parse_lines,
    parse_sources,
    stitch_multiline,
)

SYSLOG_3164 = [
    "<34>Oct 11 22:14:15 myhost su[1234]: authentication failure for admin",
    "<13>Oct 11 22:14:16 myhost cron: job finished",
]
SYSLOG_5424 = [
    "<165>1 2026-06-14T09:03:14Z host app 4711 ID47 - database connection refused",
]
LOGFMT = [
    'level=error msg="db connection failed" service=payments ts=2026-06-14T09:03:14Z',
    'level=info msg="request handled" service=api ts=2026-06-14T09:03:15Z',
]
CLF = [
    '10.0.0.1 - - [14/Jun/2026:09:03:14 +0000] "GET /api/x HTTP/1.1" 503 120 "-" "curl"',
    '10.0.0.2 - - [14/Jun/2026:09:03:15 +0000] "GET /ok HTTP/1.1" 200 50 "-" "curl"',
]


def test_detect_syslog():
    assert detect_format(SYSLOG_3164) == "syslog"
    assert detect_format(SYSLOG_5424) == "syslog"


def test_detect_logfmt_and_clf():
    assert detect_format(LOGFMT) == "logfmt"
    assert detect_format(CLF) == "clf"


def test_parse_syslog_3164_severity_from_pri():
    # PRI 34 -> severity 34 % 8 = 2 -> CRITICAL
    entry = parse_line(1, SYSLOG_3164[0], "syslog")
    assert entry.level == Severity.CRITICAL
    assert "authentication failure" in entry.message
    assert entry.timestamp is not None


def test_parse_syslog_5424_tags_component():
    entry = parse_line(1, SYSLOG_5424[0], "syslog")
    assert entry.level == Severity.NOTICE  # PRI 165 % 8 = 5
    assert entry.message.startswith("[app]")


def test_parse_logfmt_fields():
    entry = parse_line(1, LOGFMT[0], "logfmt")
    assert entry.level == Severity.ERROR
    assert entry.message == "db connection failed"
    assert entry.fields["service"] == "payments"
    assert entry.timestamp is not None


def test_parse_clf_status_to_severity():
    err = parse_line(1, CLF[0], "clf")
    ok = parse_line(2, CLF[1], "clf")
    assert err.level == Severity.ERROR
    assert ok.level == Severity.INFO
    assert "503" in err.message


def test_stitch_multiline_merges_traceback():
    lines = [
        "2026-06-14 09:03:14 ERROR boom",
        "Traceback (most recent call last):",
        '  File "app.py", line 10, in <module>',
        "    raise ValueError('x')",
        "ValueError: x",
        "2026-06-14 09:03:15 INFO next line",
    ]
    stitched = stitch_multiline(lines)
    assert len(stitched) == 2
    assert "Traceback" in stitched[0]
    assert "ValueError" in stitched[0]


def test_parse_lines_stitches_by_default():
    lines = [
        "2026-06-14 09:03:14 ERROR boom",
        "    at com.example.Foo.bar(Foo.java:42)",
        "2026-06-14 09:03:15 INFO ok",
    ]
    entries = parse_lines(lines, fmt="text")
    assert len(entries) == 2


def test_parse_file_gzip(tmp_path: Path):
    path = tmp_path / "app.log.gz"
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        fh.write("2026-06-14 09:03:14 ERROR [db] boom\n")
    entries = parse_file(str(path))
    assert len(entries) == 1
    assert entries[0].level == Severity.ERROR


def test_parse_sources_concatenates_and_renumbers(tmp_path: Path):
    a = tmp_path / "a.log"
    b = tmp_path / "b.log"
    a.write_text("2026-06-14 09:03:14 ERROR one\n", encoding="utf-8")
    b.write_text("2026-06-14 09:03:15 ERROR two\n", encoding="utf-8")
    entries = parse_sources([str(a), str(b)])
    assert [e.line_no for e in entries] == [1, 2]


def test_parse_sources_directory(tmp_path: Path):
    (tmp_path / "x.log").write_text("2026-06-14 09:03:14 ERROR a\n", encoding="utf-8")
    (tmp_path / "y.log").write_text("2026-06-14 09:03:15 ERROR b\n", encoding="utf-8")
    (tmp_path / "ignore.bin").write_text("nope\n", encoding="utf-8")
    entries = parse_sources([str(tmp_path)])
    assert len(entries) == 2


def test_text_and_json_detection_unbroken():
    assert detect_format(["2026-06-14 09:03:14 ERROR [db] boom uid=10241"]) == "text"
    assert detect_format(['{"level":"error","msg":"x"}']) == "json"
