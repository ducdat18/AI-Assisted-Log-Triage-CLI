"""Log parsing: format auto-detection plus plaintext and JSON-lines parsing.

The parser is deliberately tolerant — production logs are messy, and a triage
tool that crashes on a malformed line is useless during an incident. Every line
becomes a :class:`LogEntry`; lines we cannot fully understand still keep their
raw text so nothing is silently dropped.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum

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
    def from_text(cls, text: str | None) -> Severity | None:
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
    """Detect the log format from a sample of non-blank lines.

    Returns one of ``json``, ``syslog``, ``clf``, ``logfmt`` or ``text``. A
    specialised format is only chosen when a clear majority (≥60%) of sampled
    lines match it, so ambiguous logs fall back safely to ``text``.
    """

    hits = {"json": 0, "syslog": 0, "clf": 0, "logfmt": 0}
    seen = 0
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        seen += 1
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                json.loads(stripped)
                hits["json"] += 1
            except ValueError:
                pass
        if _SYSLOG_5424.match(stripped) or _SYSLOG_3164.match(stripped):
            hits["syslog"] += 1
        if _CLF.match(stripped):
            hits["clf"] += 1
        first_token = stripped.split(maxsplit=1)[0] if stripped.split() else ""
        if "=" in first_token and len(_LOGFMT_PAIR.findall(stripped)) >= 2:
            hits["logfmt"] += 1
        if seen >= sample_size:
            break
    if seen == 0:
        return "text"
    # Priority order: the most specific, unambiguous formats first.
    for fmt in ("json", "syslog", "clf", "logfmt"):
        if hits[fmt] / seen >= 0.6:
            return fmt
    return "text"


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
    "%b %d %H:%M:%S",  # RFC 3164 syslog (no year)
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


def _first_key(data: Mapping[str, object], keys: Iterable[str]) -> object | None:
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
_LEVEL_TOKENS = (
    "TRACE|DEBUG|DBG|INFO|NOTICE|WARN|WARNING|ERROR|ERR|FATAL|CRIT|CRITICAL|EMERGENCY|PANIC"
)
# Matches a severity token like " ERROR " / "[WARN]" / "level=error" anywhere.
_TEXT_LEVEL = re.compile(
    rf"(?<![A-Za-z])(?:level=)?\[?(?P<lvl>{_LEVEL_TOKENS})\]?(?![A-Za-z])",
    re.IGNORECASE,
)
# Same, but anchored at the start so we can strip a *leading* level prefix.
_LEADING_LEVEL = re.compile(
    rf"^(?:level=)?\[?(?P<lvl>{_LEVEL_TOKENS})\]?(?![A-Za-z])",
    re.IGNORECASE,
)


def _parse_text_line(line_no: int, raw: str) -> LogEntry:
    """Parse a plaintext line, stripping a leading timestamp and level prefix.

    The returned ``message`` is the log *body* — without the leading timestamp
    and severity token — so cluster templates and component tags aren't buried
    behind ``<TS> ERROR`` noise. A severity that appears only mid-line (e.g.
    ``level=error`` inside the body) is still detected but left in place.
    """

    body = raw.rstrip("\n").strip()
    timestamp = None
    ts_match = _TEXT_TIMESTAMP.match(body)
    if ts_match:
        timestamp = _parse_timestamp(ts_match.group("ts"))
        body = body[ts_match.end() :].lstrip()

    level = None
    leading = _LEADING_LEVEL.match(body)
    if leading:
        level = Severity.from_text(leading.group("lvl"))
        body = body[leading.end() :].lstrip()
    else:
        anywhere = _TEXT_LEVEL.search(body)
        if anywhere:
            level = Severity.from_text(anywhere.group("lvl"))

    return LogEntry(
        line_no=line_no,
        raw=raw,
        message=body,
        level=level,
        timestamp=timestamp,
    )


# --- logfmt parsing --------------------------------------------------------

_LOGFMT_PAIR = re.compile(r'(\w[\w.\-]*)=("(?:[^"\\]|\\.)*"|\S+)')


def _logfmt_pairs(line: str) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for key, value in _LOGFMT_PAIR.findall(line):
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1].replace('\\"', '"')
        pairs[key.lower()] = value
    return pairs


def _parse_logfmt_line(line_no: int, raw: str) -> LogEntry:
    """Parse a Heroku/Go-style ``key=value`` logfmt line."""

    pairs = _logfmt_pairs(raw)
    if not pairs:
        return _parse_text_line(line_no, raw)
    level = Severity.from_text(str(_first_key(pairs, _LEVEL_KEYS) or "") or None)
    message_value = _first_key(pairs, _MESSAGE_KEYS)
    message = str(message_value) if message_value is not None else raw.strip()
    time_value = _first_key(pairs, _TIME_KEYS)
    timestamp = _parse_timestamp(str(time_value)) if time_value else None
    return LogEntry(
        line_no=line_no,
        raw=raw,
        message=message,
        level=level,
        timestamp=timestamp,
        fields=dict(pairs),
    )


# --- syslog parsing (RFC 3164 & 5424) --------------------------------------

# RFC 5424: "<PRI>VERSION TIMESTAMP HOST APP PROCID MSGID [SD] MSG"
_SYSLOG_5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>\d+\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?:-|\[.*?\])\s*(?P<msg>.*)$"
)
# RFC 3164: "<PRI>Mon DD HH:MM:SS HOST TAG: MSG" (PRI optional in the wild).
_SYSLOG_3164 = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<tag>[^:\[]+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)


def _severity_from_pri(pri: str | None) -> Severity | None:
    """Map a syslog priority value to a loglens severity via its facility-3 level."""

    if pri is None:
        return None
    sev = int(pri) % 8  # 0=emerg .. 7=debug
    mapping = {
        0: Severity.CRITICAL,
        1: Severity.CRITICAL,
        2: Severity.CRITICAL,
        3: Severity.ERROR,
        4: Severity.WARNING,
        5: Severity.NOTICE,
        6: Severity.INFO,
        7: Severity.DEBUG,
    }
    return mapping.get(sev)


def _parse_syslog_line(line_no: int, raw: str) -> LogEntry:
    body = raw.rstrip("\n")
    match = _SYSLOG_5424.match(body) or _SYSLOG_3164.match(body)
    if not match:
        return _parse_text_line(line_no, raw)
    groups = match.groupdict()
    level = _severity_from_pri(groups.get("pri"))
    if level is None:
        lvl_match = _TEXT_LEVEL.search(groups["msg"])
        if lvl_match:
            level = Severity.from_text(lvl_match.group("lvl"))
    tag = groups.get("app") or groups.get("tag")
    message = groups["msg"].strip()
    if tag and tag not in ("-",):
        message = f"[{tag.strip()}] {message}"
    return LogEntry(
        line_no=line_no,
        raw=raw,
        message=message,
        level=level,
        timestamp=_parse_timestamp(groups.get("ts")),
    )


# --- Common Log Format (nginx / apache combined) ---------------------------

_CLF = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\S+)"
)


def _parse_clf_line(line_no: int, raw: str) -> LogEntry:
    """Parse an nginx/apache access line; severity is derived from HTTP status."""

    match = _CLF.match(raw)
    if not match:
        return _parse_text_line(line_no, raw)
    g = match.groupdict()
    status = int(g["status"])
    if status >= 500:
        level: Severity | None = Severity.ERROR
    elif status >= 400:
        level = Severity.WARNING
    else:
        level = Severity.INFO
    message = f"{g['method']} {g['path']} -> {status}"
    return LogEntry(
        line_no=line_no,
        raw=raw,
        message=message,
        level=level,
        timestamp=_parse_timestamp(g["ts"]),
        fields={k: g[k] for k in ("ip", "method", "path", "status")},
    )


# --- Multi-line stitching --------------------------------------------------

# A line that *continues* the previous log record rather than starting a new one:
# indented text, a stack frame, or a traceback continuation.
_CONTINUATION = re.compile(
    r"^(\s+|Traceback \(|\s*at\s+\w|\s*Caused by:|\s*\.\.\.\s+\d+\s+more|"
    r'\s*File "|\s*[A-Za-z_.]+(?:Error|Exception):)'
)


def stitch_multiline(lines: list[str]) -> list[str]:
    """Merge continuation lines (stack traces, tracebacks) into their parent.

    A continuation line — indented, a stack frame, or a ``Caused by:`` clause —
    is appended to the preceding logical line so a multi-line exception becomes a
    single :class:`LogEntry` instead of dozens of orphaned fragments.
    """

    out: list[str] = []
    for line in lines:
        if out and line.strip() and _CONTINUATION.match(line):
            out[-1] = out[-1].rstrip("\n") + "\n" + line.rstrip("\n")
        else:
            out.append(line)
    return out


# --- Public API ------------------------------------------------------------

_LINE_PARSERS = {
    "json": _parse_json_line,
    "text": _parse_text_line,
    "logfmt": _parse_logfmt_line,
    "syslog": _parse_syslog_line,
    "clf": _parse_clf_line,
}


def parse_line(line_no: int, raw: str, fmt: str) -> LogEntry:
    """Parse a single raw line according to ``fmt``.

    Supported: ``json``, ``text``, ``logfmt``, ``syslog``, ``clf``
    (nginx/apache). Unknown formats fall back to ``text``.
    """

    return _LINE_PARSERS.get(fmt, _parse_text_line)(line_no, raw)


def parse_lines(
    lines: Iterable[str], fmt: str | None = None, stitch: bool = True
) -> list[LogEntry]:
    """Parse an iterable of raw lines into :class:`LogEntry` objects.

    Blank lines are skipped. ``fmt`` is auto-detected when not provided. When
    ``stitch`` is set, multi-line stack traces are merged into one entry.
    """

    materialised = list(lines)
    if stitch:
        materialised = stitch_multiline(materialised)
    resolved_fmt = fmt or detect_format(materialised)
    entries: list[LogEntry] = []
    for index, raw in enumerate(materialised, start=1):
        if not raw.strip():
            continue
        entries.append(parse_line(index, raw, resolved_fmt))
    return entries


def _open_text(path: str):
    """Open a log file for text reading, transparently decompressing ``.gz``."""

    if path.endswith(".gz"):
        import gzip

        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")  # noqa: SIM115 (caller manages)


def parse_file(path: str, fmt: str | None = None) -> list[LogEntry]:
    """Read and parse a single log file from disk (``.gz`` is auto-decompressed)."""

    with _open_text(path) as handle:
        return parse_lines(handle, fmt)


def _expand_sources(paths: Iterable[str]) -> list[str]:
    """Expand ``-`` (stdin), directories (recursive), and plain file paths."""

    import os

    resolved: list[str] = []
    for path in paths:
        if path == "-":
            resolved.append("-")
        elif os.path.isdir(path):
            for root, _dirs, files in os.walk(path):
                resolved.extend(
                    os.path.join(root, f)
                    for f in sorted(files)
                    if f.endswith((".log", ".txt", ".jsonl", ".gz"))
                )
        else:
            resolved.append(path)
    return resolved


def parse_sources(paths: Iterable[str], fmt: str | None = None) -> list[LogEntry]:
    """Parse one or more sources: files, ``.gz`` archives, directories, or stdin.

    All entries are concatenated and renumbered sequentially. ``-`` reads stdin,
    a directory is walked for ``*.log``/``*.txt``/``*.jsonl``/``*.gz`` files.
    """

    import sys

    entries: list[LogEntry] = []
    for path in _expand_sources(paths):
        if path == "-":
            entries.extend(parse_lines(sys.stdin, fmt))
        else:
            entries.extend(parse_file(path, fmt))
    return [replace_line_no(e, i) for i, e in enumerate(entries, start=1)]


def replace_line_no(entry: LogEntry, line_no: int) -> LogEntry:
    """Return a copy of ``entry`` with a new sequential line number."""

    from dataclasses import replace

    return replace(entry, line_no=line_no)
