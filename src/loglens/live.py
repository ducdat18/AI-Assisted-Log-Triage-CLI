"""Shared live-tail machinery for the ``watch`` CLI and the web dashboard SSE.

Both the terminal ``loglens watch`` command and the dashboard's realtime stream
need the same thing: follow a growing log file, parse each new line, keep only
what clears a severity threshold, and flag the first sighting of each distinct
signature. That logic lives here once so the two surfaces cannot drift apart.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime

from .clustering import normalize
from .parser import Severity, detect_format, parse_line
from .redact import redact_text


@dataclass(frozen=True)
class SurfacedLine:
    """One log line surfaced by the tailer, ready to render or stream."""

    line_no: int
    timestamp: datetime | None
    level: Severity
    message: str  # already redacted when redaction is on
    template: str
    is_new: bool  # first time this signature is seen in the session


def resolve_format(path: str, fmt: str | None = None, sample: int = 20) -> str:
    """Resolve the log format for ``path``, auto-detecting from a head sample."""

    if fmt:
        return fmt
    with open(path, encoding="utf-8", errors="replace") as handle:
        head = [next(handle, "") for _ in range(sample)]
    return detect_format(head)


def tail_lines(path: str, poll_interval: float = 0.5, from_end: bool = True) -> Iterator[str]:
    """Yield new lines appended to ``path`` (like ``tail -f``), forever.

    Starts at end of file when ``from_end`` so only *new* lines are surfaced.
    Blocks between reads for ``poll_interval`` seconds. Caller stops by breaking
    out of the iteration (or ``KeyboardInterrupt``).
    """

    with open(path, encoding="utf-8", errors="replace") as handle:
        if from_end:
            handle.seek(0, 2)
        while True:
            line = handle.readline()
            if not line:
                time.sleep(poll_interval)
                continue
            yield line


def tail_entries(
    path: str,
    fmt: str | None = None,
    threshold: Severity = Severity.ERROR,
    redact: bool = False,
    poll_interval: float = 0.5,
    from_end: bool = True,
) -> Iterator[SurfacedLine]:
    """Tail ``path`` and yield :class:`SurfacedLine` for entries at/above ``threshold``."""

    resolved_fmt = resolve_format(path, fmt)
    seen: set[str] = set()
    line_no = 0
    for raw in tail_lines(path, poll_interval=poll_interval, from_end=from_end):
        line_no += 1
        if not raw.strip():
            continue
        entry = parse_line(line_no, raw, resolved_fmt)
        if entry.level is None or entry.level < threshold:
            continue
        template = normalize(entry.message)
        is_new = template not in seen
        seen.add(template)
        message = redact_text(entry.message) if redact else entry.message
        yield SurfacedLine(
            line_no=line_no,
            timestamp=entry.timestamp,
            level=entry.level,
            message=message,
            template=template,
            is_new=is_new,
        )
