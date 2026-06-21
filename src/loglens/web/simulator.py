"""A synthetic incident log generator for the dashboard's "Simulate" button.

Triage tools are hard to *show* without a live incident. This writes a realistic,
escalating incident — a database primary failing and cascading into persistence
and world-simulation faults — into a file, one line at a time with live
timestamps, so the dashboard's live-tail and analysis update in real time.

No external source file is required; it works the same in Docker and locally.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime
from pathlib import Path


def incident_script() -> list[tuple[str, str, float]]:
    """An ordered ``(level, message, delay_seconds)`` incident.

    The shape is deliberate so the dashboard shows *all* of loglens's signals:
    a slow healthy warm-up gives anomaly detection a quiet baseline (so the
    **onset** stands out), then a fast, **interleaved** burst of DB + persistence
    errors packs into shared time-buckets (so the **cascade** db→persistence and
    **bursts** are detected), with DB emitted first so it is the trigger.
    """

    lines: list[tuple[str, str, float]] = []
    # Healthy warm-up, spread out (1s apart) to establish a zero-error baseline.
    for i in range(6):
        lines.append(("INFO", f"[api] request handled in {10 + i}ms", 1.0))
    lines.append(("WARNING", "[worldsim] Tick budget exceeded: 18.4ms on shard 7", 0.4))
    # The trigger: DB timeouts appear first.
    for i in range(2):
        lines.append(
            ("ERROR", f"[db] Connection to 10.0.4.21:5432 failed: timeout after {5 + i}s", 0.2)
        )
    # Interleaved DB + persistence so they co-occur in the same buckets (cascade).
    for i in range(6):
        lines.append(
            ("ERROR", f"[db] Connection to 10.0.4.21:5432 failed: timeout after {7 + i}s", 0.2)
        )
        lines.append(
            (
                "ERROR",
                f"[persistence] Failed to flush player state uid={10000 + i}: db pool exhausted",
                0.2,
            )
        )
    lines.append(
        ("CRITICAL", "[persistence] Write-ahead log backlog 50000 entries, dropping writes", 0.2)
    )
    lines.append(("CRITICAL", "[worldsim] Shard 7 unresponsive for 30s, failover", 0.2))
    for i in range(3):
        lines.append(("WARNING", f"[matchmaker] Queue backpressure: {1000 + i * 100} waiting", 0.2))
    return lines


def format_line(level: str, message: str, when: datetime) -> str:
    """Render one line in loglens's default plaintext shape (ts + level + body)."""

    return f"{when:%Y-%m-%d %H:%M:%S} {level} {message}"


class Simulator:
    """Appends the incident script to a target file on a background thread."""

    def __init__(self, target: str | Path) -> None:
        self.target = Path(target)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, speed: float = 1.0) -> None:
        """Reset the target file and start emitting the incident.

        ``speed`` scales the per-line delays (``speed=2`` plays twice as fast);
        clamped to a sane range by the caller.
        """

        if self.running:
            return
        self._stop.clear()
        self.target.write_text("", encoding="utf-8")  # fresh incident each run
        self._thread = threading.Thread(target=self._run, args=(speed,), daemon=True)
        self._thread.start()

    def _run(self, speed: float) -> None:
        for level, message, delay in incident_script():
            if self._stop.is_set():
                return
            line = format_line(level, message, datetime.now())
            with open(self.target, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
            time.sleep(delay / speed)

    def stop(self) -> None:
        self._stop.set()
