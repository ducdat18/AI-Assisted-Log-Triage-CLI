"""Ship loglens-enriched log entries to Grafana Loki.

What loglens adds over a plain shipper (Promtail/Alloy): every pushed entry
carries a ``cluster`` label — a stable hash of its normalized signature — so in
Grafana you can group thousands of near-identical errors into one series with
``sum by (cluster) (count_over_time(...))``. Severity is exposed as a ``level``
label for rate panels and filtering.

Uses Loki's HTTP push API (``POST /loki/api/v1/push``) directly, so no extra
agent is required for a demo or one-shot ingest.
"""

from __future__ import annotations

import hashlib
import time

import requests

from ..clustering import normalize
from ..parser import LogEntry
from ..redact import redact_text

DEFAULT_LOKI_URL = "http://localhost:3100"
_PUSH_PATH = "/loki/api/v1/push"


class LokiError(RuntimeError):
    """Raised when pushing to Loki fails."""


def signature(message: str) -> str:
    """Stable short hash of a message's normalized cluster template."""

    return hashlib.sha1(normalize(message).encode("utf-8")).hexdigest()[:10]


def _entry_timestamp_ns(entry: LogEntry, base_ns: int, index: int) -> int:
    """Nanosecond timestamp for a Loki value.

    Real timestamps are used when present; otherwise entries are anchored at
    ingest time and nudged by their index so each stream stays ordered (Loki
    requires ascending timestamps within a stream).
    """

    if entry.timestamp is not None:
        return int(entry.timestamp.timestamp() * 1_000_000_000)
    return base_ns + index


def build_streams(
    entries: list[LogEntry],
    source: str,
    redact: bool = False,
) -> list[dict[str, object]]:
    """Group entries into Loki streams keyed by ``(level, cluster)``.

    Returns the ``streams`` array of a Loki push payload. Values within each
    stream are sorted ascending by timestamp.
    """

    base_ns = int(time.time() * 1_000_000_000)
    grouped: dict[tuple[str, str], list[tuple[int, str]]] = {}
    for index, entry in enumerate(entries):
        level = entry.level.name.lower() if entry.level is not None else "unknown"
        cluster = signature(entry.message)
        line = entry.raw.rstrip("\n")
        if redact:
            line = redact_text(line)
        ts_ns = _entry_timestamp_ns(entry, base_ns, index)
        grouped.setdefault((level, cluster), []).append((ts_ns, line))

    streams: list[dict[str, object]] = []
    for (level, cluster), values in grouped.items():
        values.sort(key=lambda pair: pair[0])
        streams.append(
            {
                "stream": {
                    "job": "loglens",
                    "source": source,
                    "level": level,
                    "cluster": cluster,
                },
                "values": [[str(ts_ns), line] for ts_ns, line in values],
            }
        )
    return streams


class LokiClient:
    """Minimal client for Loki's HTTP push API."""

    def __init__(self, url: str = DEFAULT_LOKI_URL, timeout: float = 30.0) -> None:
        self.url = url.rstrip("/")
        self.timeout = timeout

    @property
    def push_endpoint(self) -> str:
        return f"{self.url}{_PUSH_PATH}"

    def push(self, streams: list[dict[str, object]]) -> int:
        """Push ``streams`` to Loki. Returns the number of entries shipped."""

        if not streams:
            return 0
        entry_count = sum(len(s["values"]) for s in streams)  # type: ignore[arg-type]
        try:
            response = requests.post(
                self.push_endpoint,
                json={"streams": streams},
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
            )
        except requests.exceptions.ConnectionError as exc:
            raise LokiError(
                f"Could not reach Loki at {self.url}. Is it running? "
                "Try the bundled stack: `docker compose -f deploy/docker-compose.yml up -d`."
            ) from exc
        except requests.RequestException as exc:  # pragma: no cover - network
            raise LokiError(f"Loki request failed: {exc}") from exc

        # Loki returns 204 No Content on a successful push.
        if response.status_code not in (200, 204):
            raise LokiError(
                f"Loki rejected the push (HTTP {response.status_code}): "
                f"{response.text[:300]}"
            )
        return entry_count
