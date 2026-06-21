"""Group log lines into error clusters by structural similarity, then rank them.

Real incident logs repeat the same error thousands of times with varying ids,
timestamps and addresses. We collapse each line to a *template* (variable parts
masked) so that "Connection to 10.0.0.1 failed" and "Connection to 10.0.0.9
failed" land in the same cluster. Clusters are then scored by a blend of
severity and frequency so the LLM only sees what matters.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import datetime

from .parser import LogEntry, Severity

# Substitutions that turn a concrete message into a stable template. Applied in
# order; each replaces a class of "variable" token with a placeholder.
_TEMPLATE_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-" r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
        "<UUID>",
    ),
    (
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}" r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d+)?\b"
        ),
        "<IP>",
    ),
    (re.compile(r"0x[0-9a-fA-F]+"), "<HEX>"),
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<HASH>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b"), "<TS>"),
    (re.compile(r"/[\w./\-]+"), "<PATH>"),
    (re.compile(r"\b\d+(?:\.\d+)?(?:ms|s|kb|mb|gb)?\b", re.IGNORECASE), "<NUM>"),
    (re.compile(r'"[^"]*"'), "<STR>"),
    (re.compile(r"'[^']*'"), "<STR>"),
    (re.compile(r"\s+"), " "),
)


def normalize(message: str) -> str:
    """Collapse a concrete log message into a stable similarity template."""

    template = message.strip()
    for pattern, replacement in _TEMPLATE_RULES:
        template = pattern.sub(replacement, template)
    return template.strip()


# A leading "[component]" / "(component)" tag identifies the emitting subsystem
# in most structured app logs, e.g. "[db] Connection ... failed".
_COMPONENT_RE = re.compile(r"^[\s>]*[\[(](?P<comp>[A-Za-z0-9_.\-/]+)[\])]")


def component_of(message: str) -> str | None:
    """Extract the emitting component from a log message, if tagged.

    Recognises a leading ``[name]`` or ``(name)`` tag. Returns ``None`` when no
    component prefix is present.
    """

    match = _COMPONENT_RE.match(message)
    return match.group("comp") if match else None


@dataclass
class Cluster:
    """A group of structurally-similar log entries."""

    template: str
    level: Severity | None
    entries: list[LogEntry] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.entries)

    @property
    def representative(self) -> LogEntry:
        """A concrete example line for display / LLM context."""

        return self.entries[0]

    @property
    def component(self) -> str | None:
        """The subsystem this cluster's errors come from, if identifiable.

        Tried in order: a structured ``service``/``component``/``module``/``logger``
        field (JSON logs), then a leading ``[name]`` tag in the message text.
        """

        fields = self.representative.fields
        for key in ("service", "component", "module", "logger", "subsystem"):
            value = fields.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return component_of(self.template) or component_of(self.representative.message)

    @property
    def first_seen(self) -> datetime | None:
        stamps = [e.timestamp for e in self.entries if e.timestamp]
        return min(stamps) if stamps else None

    @property
    def last_seen(self) -> datetime | None:
        stamps = [e.timestamp for e in self.entries if e.timestamp]
        return max(stamps) if stamps else None

    def severity_score(self) -> float:
        """Rank weight: severity dominates strictly, frequency breaks ties.

        Severity is scaled by a large constant so a more severe cluster always
        outranks a less severe one regardless of volume (a single CRITICAL is
        never buried under thousands of WARNINGs). Within one severity level,
        ``log1p`` of the count rewards genuinely high-volume errors without
        letting frequency dominate.
        """

        level_weight = float(self.level) if self.level is not None else float(Severity.INFO)
        return level_weight * 1000.0 + math.log1p(self.count)


def cluster_entries(
    entries: list[LogEntry],
    min_level: Severity | None = Severity.WARNING,
) -> list[Cluster]:
    """Cluster entries by template.

    ``min_level`` filters out anything below the threshold (default: only
    WARNING and above, since that is what triage cares about). Pass ``None`` to
    cluster everything.
    """

    clusters: dict[tuple[str, int], Cluster] = {}
    for entry in entries:
        if min_level is not None and (entry.level is None or entry.level < min_level):
            continue
        template = normalize(entry.message)
        key = (template, int(entry.level) if entry.level is not None else -1)
        cluster = clusters.get(key)
        if cluster is None:
            cluster = Cluster(template=template, level=entry.level)
            clusters[key] = cluster
        cluster.entries.append(entry)
    return list(clusters.values())


def cluster_entries_drain(
    entries: list[LogEntry],
    min_level: Severity | None = Severity.WARNING,
    sim_th: float = 0.4,
) -> list[Cluster]:
    """Cluster entries with the Drain template miner instead of regex templates.

    Drain learns templates structurally (see :mod:`loglens.drain`), so it adapts
    to message shapes the hand-written regex rules don't cover. Grouping is keyed
    on Drain's stable group id *and* severity, mirroring the regex path.
    """

    from .drain import DrainMiner  # local import: optional code path

    filtered = [
        e for e in entries if min_level is None or (e.level is not None and e.level >= min_level)
    ]
    miner = DrainMiner(sim_th=sim_th)
    assignments = [(e, miner.add_id(e.message)) for e in filtered]
    templates = miner.templates()

    clusters: dict[tuple[int, int], Cluster] = {}
    for entry, gid in assignments:
        key = (gid, int(entry.level) if entry.level is not None else -1)
        cluster = clusters.get(key)
        if cluster is None:
            cluster = Cluster(template=templates.get(gid, entry.message), level=entry.level)
            clusters[key] = cluster
        cluster.entries.append(entry)
    return list(clusters.values())


def rank_clusters(clusters: list[Cluster], top_n: int | None = None) -> list[Cluster]:
    """Return clusters sorted by descending severity score."""

    ranked = sorted(clusters, key=lambda c: c.severity_score(), reverse=True)
    return ranked[:top_n] if top_n is not None else ranked


def cluster_and_rank(
    entries: list[LogEntry],
    top_n: int | None = None,
    min_level: Severity | None = Severity.WARNING,
    method: str = "regex",
) -> list[Cluster]:
    """Convenience pipeline: cluster then rank in one call.

    ``method`` selects the clusterer: ``"regex"`` (default, fast hand-written
    templating) or ``"drain"`` (structural Drain template mining).
    """

    if method == "drain":
        clustered = cluster_entries_drain(entries, min_level=min_level)
    else:
        clustered = cluster_entries(entries, min_level=min_level)
    return rank_clusters(clustered, top_n=top_n)
