"""Infer a severity for log lines that arrive without an explicit level.

Plenty of real logs carry no level field — bare ``print`` output, third-party
components, custom formats. Those lines are invisible to severity-gated triage
even when they say "Traceback" or "connection refused". This module assigns a
best-effort severity from the message text so they are not silently dropped.

It is a transparent lexical classifier: ordered keyword sets, most-severe first.
An optional scikit-learn backend (extra ``[ml]``) can be slotted in later behind
the same :func:`infer_severity` signature; the heuristic is the always-available
default and keeps the tool dependency-free.
"""

from __future__ import annotations

import re
from dataclasses import replace

from .parser import LogEntry, Severity

# Ordered most-severe first; the first matching tier wins. Patterns are matched
# case-insensitively against the message text as whole words where it matters.
_TIERS: tuple[tuple[Severity, tuple[str, ...]], ...] = (
    (
        Severity.CRITICAL,
        (
            "panic",
            "fatal",
            "segfault",
            "segmentation fault",
            "out of memory",
            "oom",
            "emergency",
            "unrecoverable",
            "data loss",
            "corruption",
            "kernel",
            "core dumped",
        ),
    ),
    (
        Severity.ERROR,
        (
            "error",
            "exception",
            "traceback",
            "stack trace",
            "stacktrace",
            "failed",
            "failure",
            "cannot",
            "could not",
            "couldn't",
            "unable",
            "refused",
            "timeout",
            "timed out",
            "denied",
            "rejected",
            "crash",
            "abort",
            "unhandled",
            "500",
            "502",
            "503",
            "504",
        ),
    ),
    (
        Severity.WARNING,
        (
            "warn",
            "warning",
            "deprecated",
            "deprecation",
            "retry",
            "retrying",
            "slow",
            "throttl",
            "degraded",
            "fallback",
            "high latency",
            "backpressure",
            "near capacity",
            "429",
        ),
    ),
)

# Pre-compile one alternation per tier for speed and word-ish boundaries.
_TIER_RES: tuple[tuple[Severity, re.Pattern[str]], ...] = tuple(
    (level, re.compile("|".join(re.escape(k) for k in keywords), re.IGNORECASE))
    for level, keywords in _TIERS
)


def infer_severity(message: str) -> Severity | None:
    """Best-effort severity from message text, or ``None`` if nothing matches.

    Conservative by design: only WARNING and above are inferred, so a line is
    never *promoted* into triage without a concrete textual signal.
    """

    for level, pattern in _TIER_RES:
        if pattern.search(message):
            return level
    return None


def apply_inference(entries: list[LogEntry]) -> tuple[list[LogEntry], int]:
    """Fill in missing levels by inference; return (new entries, count filled).

    Entries that already have a level are returned unchanged. The input list is
    not mutated — new :class:`LogEntry` objects are produced for filled lines.
    """

    result: list[LogEntry] = []
    filled = 0
    for entry in entries:
        if entry.level is None:
            inferred = infer_severity(entry.message)
            if inferred is not None:
                entry = replace(entry, level=inferred)
                filled += 1
        result.append(entry)
    return result, filled
