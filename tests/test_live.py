"""Tests for the shared live-tail module."""

from __future__ import annotations

from itertools import islice
from pathlib import Path

from loglens.live import resolve_format, tail_entries
from loglens.parser import Severity


def test_resolve_format_detects(tmp_path: Path):
    f = tmp_path / "a.log"
    f.write_text("2026-06-14 09:03:14 ERROR boom\n", encoding="utf-8")
    assert resolve_format(str(f)) == "text"
    assert resolve_format(str(f), "json") == "json"


def test_tail_entries_filters_and_flags_new(tmp_path: Path):
    f = tmp_path / "app.log"
    f.write_text(
        "2026-06-14 09:03:14 INFO quiet\n"
        "2026-06-14 09:03:15 ERROR [db] timeout\n"
        "2026-06-14 09:03:16 ERROR [db] timeout\n"
        "2026-06-14 09:03:17 CRITICAL [pay] down\n",
        encoding="utf-8",
    )
    # from_end=False so we read the existing lines; islice stops before EOF block.
    surfaced = list(islice(tail_entries(str(f), threshold=Severity.ERROR, from_end=False), 3))
    assert [s.level for s in surfaced] == [Severity.ERROR, Severity.ERROR, Severity.CRITICAL]
    assert surfaced[0].is_new is True  # first db timeout
    assert surfaced[1].is_new is False  # same signature
    assert surfaced[2].is_new is True  # different signature


def test_tail_entries_redacts(tmp_path: Path):
    f = tmp_path / "r.log"
    f.write_text("2026-06-14 09:03:15 ERROR login failed for admin@corp.com\n", encoding="utf-8")
    surfaced = list(
        islice(tail_entries(str(f), threshold=Severity.ERROR, redact=True, from_end=False), 1)
    )
    assert "admin@corp.com" not in surfaced[0].message
