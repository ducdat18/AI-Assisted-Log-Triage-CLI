"""Tests for lexical severity inference (1d)."""

from __future__ import annotations

from loglens.parser import LogEntry, Severity
from loglens.severity_infer import apply_inference, infer_severity


def test_infer_critical_beats_error_keywords():
    # "fatal" (CRITICAL) outranks "error" present in the same line.
    assert infer_severity("fatal error: kernel panic") == Severity.CRITICAL


def test_infer_error_from_text():
    assert infer_severity("Traceback (most recent call last)") == Severity.ERROR
    assert infer_severity("connection refused to upstream") == Severity.ERROR
    assert infer_severity("returned HTTP 503") == Severity.ERROR


def test_infer_warning_from_text():
    assert infer_severity("API is deprecated, please migrate") == Severity.WARNING
    assert infer_severity("retrying request after backoff") == Severity.WARNING


def test_infer_none_when_no_signal():
    assert infer_severity("user alice viewed dashboard") is None


def test_apply_inference_fills_only_unlabeled():
    entries = [
        LogEntry(line_no=1, raw="x", message="all good", level=Severity.INFO),
        LogEntry(line_no=2, raw="y", message="connection timeout", level=None),
        LogEntry(line_no=3, raw="z", message="nothing notable", level=None),
    ]
    result, filled = apply_inference(entries)
    assert filled == 1
    assert result[0].level == Severity.INFO  # untouched
    assert result[1].level == Severity.ERROR  # inferred
    assert result[2].level is None  # no signal
    # Input not mutated.
    assert entries[1].level is None
