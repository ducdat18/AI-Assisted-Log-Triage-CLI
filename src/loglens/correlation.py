"""Cross-cluster correlation and cascade reconstruction — deterministic, no LLM.

During an incident, one fault triggers others: a database goes down, the
persistence layer starts failing, then the world simulation stalls. The sample
report in the README shows an LLM *inferring* that chain. This module computes
it instead, from timestamps alone.

Two clusters are *temporally correlated* when they fire in the same time
windows. We bucket each cluster's events into a shared grid, build a per-cluster
occupancy vector, and measure overlap with the Jaccard index. A cascade link is
proposed from cluster A to cluster B when they are correlated **and** A's first
occurrence precedes B's — A is a plausible cause, B a plausible effect, with the
lag between them reported.

The earliest high-severity cluster that has downstream effects is surfaced as
the likely **trigger**. None of this asks a model anything; it is evidence the
narration layer can stand on.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .clustering import Cluster
from .parser import Severity

# A link is only proposed when bucket overlap and lag are within these bounds.
_MIN_JACCARD = 0.2
_MAX_LAG_SECONDS = 600.0


@dataclass(frozen=True)
class TimelineEvent:
    """One cluster placed on the incident timeline by first appearance."""

    order: int
    first_seen: datetime
    last_seen: datetime
    level: Severity | None
    count: int
    component: str | None
    template: str


@dataclass(frozen=True)
class CascadeLink:
    """A proposed cause → effect relationship between two clusters."""

    cause: int  # index into timeline
    effect: int
    lag_seconds: float
    jaccard: float


@dataclass(frozen=True)
class CorrelationReport:
    """The reconstructed incident timeline plus inferred cascade structure."""

    timeline: tuple[TimelineEvent, ...]
    links: tuple[CascadeLink, ...]
    trigger: int | None  # index into timeline, or None

    @property
    def has_cascade(self) -> bool:
        return bool(self.links)


def _occupancy(cluster: Cluster, origin: datetime, bucket_seconds: int) -> frozenset[int]:
    """The set of bucket indices in which this cluster has at least one event."""

    indices = set()
    for entry in cluster.entries:
        if entry.timestamp is None:
            continue
        indices.add(int((entry.timestamp - origin).total_seconds() // bucket_seconds))
    return frozenset(indices)


def _jaccard(a: frozenset[int], b: frozenset[int]) -> float:
    if not a or not b:
        return 0.0
    union = len(a | b)
    return len(a & b) / union if union else 0.0


def correlate_clusters(clusters: list[Cluster], bucket_seconds: int) -> CorrelationReport:
    """Build the incident timeline and infer cause→effect cascade links.

    Only clusters with at least one timestamped event participate. ``bucket_seconds``
    should match the grid used for anomaly detection so the two analyses agree.
    """

    timed = [c for c in clusters if any(e.timestamp for e in c.entries)]
    if not timed:
        return CorrelationReport(timeline=(), links=(), trigger=None)

    def first_seen(c: Cluster) -> datetime:
        return min(e.timestamp for e in c.entries if e.timestamp)  # type: ignore[type-var]

    ordered = sorted(timed, key=first_seen)
    origin = first_seen(ordered[0])

    timeline = tuple(
        TimelineEvent(
            order=i,
            first_seen=first_seen(c),
            last_seen=max(e.timestamp for e in c.entries if e.timestamp),  # type: ignore[type-var]
            level=c.level,
            count=c.count,
            component=c.component,
            template=c.template,
        )
        for i, c in enumerate(ordered)
    )
    occupancy = [_occupancy(c, origin, bucket_seconds) for c in ordered]

    links: list[CascadeLink] = []
    for effect in range(len(ordered)):
        best: CascadeLink | None = None
        for cause in range(effect):
            if timeline[cause].first_seen >= timeline[effect].first_seen:
                continue
            lag = (timeline[effect].first_seen - timeline[cause].first_seen).total_seconds()
            if lag > _MAX_LAG_SECONDS:
                continue
            score = _jaccard(occupancy[cause], occupancy[effect])
            if score < _MIN_JACCARD:
                continue
            if best is None or score > best.jaccard:
                best = CascadeLink(cause=cause, effect=effect, lag_seconds=lag, jaccard=round(score, 3))
        if best is not None:
            links.append(best)

    trigger = _pick_trigger(timeline, links)
    return CorrelationReport(timeline=timeline, links=tuple(links), trigger=trigger)


def _pick_trigger(timeline: tuple[TimelineEvent, ...], links: tuple[CascadeLink, ...]) -> int | None:
    """The trigger is the earliest severe cluster that causes downstream effects.

    Preference order: a cause that is never itself an effect (a true root),
    breaking ties by earliest ``first_seen`` and higher severity. Falls back to
    the earliest ERROR+ cluster, then to the earliest cluster overall.
    """

    if timeline == ():
        return None

    causes = {link.cause for link in links}
    effects = {link.effect for link in links}
    roots = [i for i in causes if i not in effects]

    def severity(i: int) -> float:
        lvl = timeline[i].level
        return float(lvl) if lvl is not None else 0.0

    if roots:
        return min(roots, key=lambda i: (timeline[i].first_seen, -severity(i)))

    severe = [e.order for e in timeline if e.level is not None and e.level >= Severity.ERROR]
    if severe:
        return min(severe, key=lambda i: timeline[i].first_seen)
    return timeline[0].order
