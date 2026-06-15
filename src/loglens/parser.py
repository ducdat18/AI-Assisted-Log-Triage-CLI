"""Log parsing: format auto-detection plus plaintext and JSON-lines parsing.

The parser is deliberately tolerant — production logs are messy, and a triage
tool that crashes on a malformed line is useless during an incident. Every line
becomes a :class:`LogEntry`; lines we cannot fully understand still keep their
raw text so nothing is silently dropped.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Iterable

# --- Severity levels -------------------------------------------------------


class Severity(IntEnum):
    """Ordered severity. Higher value == more severe."""

    TRACE = 5
    DEBUG = 10
    INFO = 20
    NOTICE = 25
    WARNING = 30
    ERROR = 40
    CRITICAL = 50

    @classmethod
    def from_text(cls, text: str | None) -> "Severity | None":
        if not text:
            return None
        return _LEVEL_ALIASES.get(text.strip().upper())


_LEVEL_ALIASES: dict[str, Severity] = {
    "TRACE": Severity.TRACE,
    "DEBUG": Severity.DEBUG,
    "DBG": Severity.DEBUG,
    "INFO": Severity.INFO,
    "INFORMATION": Severity.INFO,
    "NOTICE": Severity.NOTICE,
    "WARN": Severity.WARNING,
    "WARNING": Severity.WARNING,
    "ERROR": Severity.ERROR,
    "ERR": Severity.ERROR,
    "FATAL": Severity.CRITICAL,
    "CRIT": Severity.CRITICAL,
    "CRITICAL": Severity.CRITICAL,
    "EMERGENCY": Severity.CRITICAL,
    "PANIC": Severity.CRITICAL,
}


# --- Data model ------------------------------------------------------------


@dataclass(frozen=True)
class LogEntry:
    """A single parsed log line. Immutable by design."""

    line_no: int
    raw: str
    message: str
    level: Severity | None = None
    timestamp: datetime | None = None
    fields: dict[str, object] = field(default_factory=dict)

    @property
    def is_error(self) -> bool:
        return self.level is not None and self.level >= Severity.ERROR


# --- Format detection ------------------------------------------------------


def detect_format(lines: Iterable[str], sample_size: int = 20) -> str:
    """Return ``"json"`` or ``"text"`` based on a sample of non-blank lines."""

    json_hits = 0
    seen = 0
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        seen += 1
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                json.loads(stripped)
                json_hits += 1
            except ValueError:
                pass
        if seen >= sample_size:
            break
    if seen == 0:
        return "text"
    # Treat as JSON-lines only if the clear majority of lines parse as JSON.
    return "json" if json_hits / seen >= 0.6 else "text"


# --- Timestamp parsing -----------------------------------------------------

_TIMESTAMP_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",
)


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip().strip("[]")
    # Normalise trailing "Z" which strptime's %z does not accept directly.
    normalised = text[:-1] + "+0000" if text.endswith("Z") else text
    for fmt in _TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(normalised, fmt)
        except ValueError:
            continue
    return None


# --- JSON-lines parsing ----------------------------------------------------

_LEVEL_KEYS = ("level", "lvl", "severity", "loglevel", "log_level")
_MESSAGE_KEYS = ("message", "msg", "text", "event", "error")
_TIME_KEYS = ("timestamp", "time", "ts", "@timestamp", "datetime", "date")


def _first_key(data: dict[str, object], keys: Iterable[str]) -> object | None:
    for key in keys:
        if key in data and data[key] not in (None, ""):
            return data[key]
    return None


def _parse_json_line(line_no: int, raw: str) -> LogEntry:
    stripped = raw.strip()
    try:
        data = json.loads(stripped)
    except ValueError:
        return _parse_text_line(line_no, raw)
    if not isinstance(data, dict):
        return LogEntry(line_no=line_no, raw=raw, message=stripped)

    level = Severity.from_text(str(_first_key(data, _LEVEL_KEYS) or "") or None)
    message_value = _first_key(data, _MESSAGE_KEYS)
    message = str(message_value) if message_value is not None else stripped
    timestamp = _parse_timestamp(
        str(_first_key(data, _TIME_KEYS)) if _first_key(data, _TIME_KEYS) else None
    )
    return LogEntry(
        line_no=line_no,
        raw=raw,
        message=message,
        level=level,
        timestamp=timestamp,
        fields=data,
    )


# --- Plaintext parsing -----------------------------------------------------

# Matches a leading ISO-8601 / common timestamp at the start of a line.
_TEXT_TIMESTAMP = re.compile(
    r"^\[?(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\]?"
)
# Matches a severity token like " ERROR " / "[WARN]" / "level=error".
_TEXT_LEVEL = re.compile(
    r"(?<![A-Za-z])(?:level=)?\[?(?P<lvl>TRACE|DEBUG|DBG|INFO|NOTICE|WARN|WARNING|"
    r"ERROR|ERR|FATAL|CRIT|CRITICAL|EMERGENCY|PANIC)\]?(?![A-Za-z])",
    re.IGNORECASE,
)


def _parse_text_line(line_no: int, raw: str) -> LogEntry:
    text = raw.rstrip("\n")
    timestamp = None
    ts_match = _TEXT_TIMESTAMP.match(text)
    if ts_match:
        timestamp = _parse_timestamp(ts_match.group("ts"))

    level = None
    lvl_match = _TEXT_LEVEL.search(text)
    if lvl_match:
        level = Severity.from_text(lvl_match.group("lvl"))

    return LogEntry(
        line_no=line_no,
        raw=raw,
        message=text.strip(),
        level=level,
        timestamp=timestamp,
    )


# --- Public API ------------------------------------------------------------


def parse_line(line_no: int, raw: str, fmt: str) -> LogEntry:
    """Parse a single raw line according to ``fmt`` (``"json"`` or ``"text"``)."""

    if fmt == "json":
        return _parse_json_line(line_no, raw)
    return _parse_text_line(line_no, raw)


def parse_lines(lines: Iterable[str], fmt: str | None = None) -> list[LogEntry]:
    """Parse an iterable of raw lines into :class:`LogEntry` objects.

    Blank lines are skipped. ``fmt`` is auto-detected when not provided.
    """

    materialised = [line for line in lines]
    resolved_fmt = fmt or detect_format(materialised)
    entries: list[LogEntry] = []
    for index, raw in enumerate(materialised, start=1):
        if not raw.strip():
            continue
        entries.append(parse_line(index, raw, resolved_fmt))
    return entries


def parse_file(path: str, fmt: str | None = None) -> list[LogEntry]:
    """Read and parse a log file from disk."""

    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return parse_lines(handle, fmt)
