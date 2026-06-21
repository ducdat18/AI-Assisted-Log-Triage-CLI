"""Temporal anomaly detection — deterministic, no LLM.

An incident is not just "many errors"; it is a *change* in error behaviour over
time. This module buckets log entries into fixed time windows, models a moving
baseline of the error rate with an EWMA (exponentially-weighted moving average)
and its EWMA variance, and flags buckets whose error count deviates from that
baseline by more than a z-score threshold.

From those spikes it derives two things triage actually wants:

* the **onset** — the first sustained deviation, i.e. *when the incident began*;
* per-cluster **bursts** — clusters whose events are concentrated in a short
  window rather than spread evenly, which is the signature of a cascading fault.

Everything here is computed from timestamps and counts alone. It runs offline,
deterministically, and gives the LLM (or the no-LLM report) hard evidence
instead of asking a model to guess a timeline.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta

from .clustering import Cluster
from .parser import LogEntry, Severity

# A bucket size is chosen so a log spans roughly this many buckets: enough
# resolution to localise an onset, few enough that each bucket has signal.
_TARGET_BUCKETS = 40
_MIN_BUCKETS = 6
# "Nice" bucket widths in seconds, smallest first; we pick the smallest width
# that keeps the bucket count at or below the target.
_NICE_WIDTHS = (1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 1800, 3600, 7200, 21600, 86400)

# EWMA smoothing factor and the z-score above which a bucket is a "spike".
_EWMA_ALPHA = 0.3
_SPIKE_Z = 2.5


@dataclass(frozen=True)
class TimeBucket:
    """Aggregated counts for one fixed time window."""

    start: datetime
    total: int
    errors: int  # entries at ERROR or above
    warnings: int  # entries at exactly WARNING/NOTICE range (WARNING..<ERROR)


@dataclass(frozen=True)
class Spike:
    """A bucket whose error count significantly exceeds the moving baseline."""

    start: datetime
    errors: int
    baseline: float
    zscore: float


@dataclass(frozen=True)
class Burst:
    """A cluster whose events are concentrated in a short window."""

    template: str
    level: Severity | None
    count: int
    peak_start: datetime
    peak_count: int  # events within the densest single bucket
    concentration: float  # peak_count / count, in (0, 1]


@dataclass(frozen=True)
class AnomalyReport:
    """Everything the temporal analysis found, ready to render or feed an LLM."""

    bucket_seconds: int
    buckets: tuple[TimeBucket, ...]
    spikes: tuple[Spike, ...]
    bursts: tuple[Burst, ...]
    onset: datetime | None
    baseline_errors: float  # pre-onset average errors/bucket
    peak_errors: int

    @property
    def has_anomalies(self) -> bool:
        return bool(self.spikes) or bool(self.bursts)


def _is_error(level: Severity | None) -> bool:
    return level is not None and level >= Severity.ERROR


def _is_warning(level: Severity | None) -> bool:
    return level is not None and Severity.WARNING <= level < Severity.ERROR


def choose_bucket_seconds(span_seconds: float) -> int:
    """Pick a human-friendly bucket width for a log spanning ``span_seconds``."""

    if span_seconds <= 0:
        return _NICE_WIDTHS[0]
    for width in _NICE_WIDTHS:
        # Don't pick a width so large the whole log is a handful of buckets.
        if span_seconds / width <= _TARGET_BUCKETS and (
            span_seconds / width >= _MIN_BUCKETS or width == _NICE_WIDTHS[0]
        ):
            return width
    return _NICE_WIDTHS[-1]


def _timed(entries: list[LogEntry]) -> list[LogEntry]:
    return [e for e in entries if e.timestamp is not None]


def bucketize(entries: list[LogEntry], bucket_seconds: int) -> list[TimeBucket]:
    """Group timestamped entries into contiguous fixed-width buckets.

    Empty intervals between activity are emitted as zero-count buckets so the
    baseline model sees the true (gappy) shape of the error rate.
    """

    timed = _timed(entries)
    if not timed:
        return []
    width = timedelta(seconds=bucket_seconds)
    stamps = [e.timestamp for e in timed if e.timestamp is not None]
    start = min(stamps)
    end = max(stamps)

    def index_of(ts: datetime) -> int:
        return int((ts - start).total_seconds() // bucket_seconds)

    n_buckets = index_of(end) + 1
    totals = [0] * n_buckets
    errors = [0] * n_buckets
    warns = [0] * n_buckets
    for entry in timed:
        if entry.timestamp is None:
            continue
        i = index_of(entry.timestamp)
        totals[i] += 1
        if _is_error(entry.level):
            errors[i] += 1
        elif _is_warning(entry.level):
            warns[i] += 1
    return [
        TimeBucket(start=start + width * i, total=totals[i], errors=errors[i], warnings=warns[i])
        for i in range(n_buckets)
    ]


def _ewma_zscores(values: list[int], alpha: float = _EWMA_ALPHA) -> list[float]:
    """One-step-ahead z-scores against an EWMA mean and EWMA variance.

    Uses West's incremental EWMA variance so the baseline adapts as it streams.
    The z-score for each point is measured against the baseline learned from
    *prior* points only — so a spike inflates neither its own mean nor variance.
    """

    zscores: list[float] = []
    mean = float(values[0]) if values else 0.0
    var = 0.0
    for i, value in enumerate(values):
        if i == 0:
            zscores.append(0.0)
        else:
            std = math.sqrt(var)
            zscores.append(
                (value - mean) / std if std > 1e-9 else (0.0 if value <= mean else math.inf)
            )
        # Update baseline *after* scoring this point.
        delta = value - mean
        mean += alpha * delta
        var = (1 - alpha) * (var + alpha * delta * delta)
    return zscores


def _detect_onset(buckets: list[TimeBucket], spikes: list[Spike]) -> datetime | None:
    """The incident onset is the start of the first error spike."""

    return spikes[0].start if spikes else None


def _detect_bursts(clusters: list[Cluster], bucket_seconds: int, min_count: int = 4) -> list[Burst]:
    """Flag clusters whose events pile up in one window instead of spreading out.

    A cluster is "bursty" when a large fraction of its events fall inside a
    single bucket-width window. Even-paced background noise stays below the
    concentration threshold; a cascading failure spikes above it.
    """

    bursts: list[Burst] = []
    width = timedelta(seconds=bucket_seconds)
    for cluster in clusters:
        stamps = sorted(e.timestamp for e in cluster.entries if e.timestamp)
        if len(stamps) < min_count:
            continue
        # Densest window via a two-pointer sweep over sorted timestamps.
        peak_count = 1
        peak_start = stamps[0]
        left = 0
        for right in range(len(stamps)):
            while stamps[right] - stamps[left] > width:
                left += 1
            window = right - left + 1
            if window > peak_count:
                peak_count = window
                peak_start = stamps[left]
        concentration = peak_count / len(stamps)
        if concentration >= 0.6:
            bursts.append(
                Burst(
                    template=cluster.template,
                    level=cluster.level,
                    count=cluster.count,
                    peak_start=peak_start,
                    peak_count=peak_count,
                    concentration=concentration,
                )
            )
    bursts.sort(key=lambda b: (b.peak_count, b.concentration), reverse=True)
    return bursts


def detect_anomalies(
    entries: list[LogEntry],
    clusters: list[Cluster] | None = None,
    bucket_seconds: int | None = None,
) -> AnomalyReport:
    """Run the full temporal analysis over ``entries``.

    ``clusters`` (already ranked) are used only for per-cluster burst detection;
    pass ``None`` to skip it. ``bucket_seconds`` is auto-chosen from the log's
    time span when not given.
    """

    timed = _timed(entries)
    if not timed:
        return AnomalyReport(
            bucket_seconds=bucket_seconds or _NICE_WIDTHS[0],
            buckets=(),
            spikes=(),
            bursts=(),
            onset=None,
            baseline_errors=0.0,
            peak_errors=0,
        )

    stamps = [e.timestamp for e in timed if e.timestamp is not None]
    span = (max(stamps) - min(stamps)).total_seconds()
    width = bucket_seconds or choose_bucket_seconds(span)
    buckets = bucketize(timed, width)

    error_series = [b.errors for b in buckets]
    zscores = _ewma_zscores(error_series)
    spikes = [
        Spike(start=b.start, errors=b.errors, baseline=0.0, zscore=z)
        for b, z in zip(buckets, zscores, strict=False)
        if z >= _SPIKE_Z and b.errors > 0
    ]
    # Backfill each spike's baseline (mean of error buckets strictly before it).
    spikes = _attach_baselines(buckets, spikes, error_series)

    onset = _detect_onset(buckets, spikes)
    pre = [b.errors for b in buckets if onset is None or b.start < onset]
    baseline_errors = sum(pre) / len(pre) if pre else 0.0
    bursts = _detect_bursts(clusters or [], width)

    return AnomalyReport(
        bucket_seconds=width,
        buckets=tuple(buckets),
        spikes=tuple(spikes),
        bursts=tuple(bursts),
        onset=onset,
        baseline_errors=round(baseline_errors, 3),
        peak_errors=max(error_series) if error_series else 0,
    )


def _attach_baselines(
    buckets: list[TimeBucket], spikes: list[Spike], error_series: list[int]
) -> list[Spike]:
    """Replace each spike's placeholder baseline with the prior-bucket mean."""

    start_to_index = {b.start: i for i, b in enumerate(buckets)}
    result: list[Spike] = []
    for spike in spikes:
        i = start_to_index[spike.start]
        prior = error_series[:i] or [0]
        result.append(
            Spike(
                start=spike.start,
                errors=spike.errors,
                baseline=round(sum(prior) / len(prior), 3),
                zscore=spike.zscore,
            )
        )
    return result
