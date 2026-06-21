"""Diff two logs by their error signatures — what's new, gone, or worse.

Comparing a "before" and "after" log (e.g. across a deploy) is one of the most
common triage questions: *did this change introduce or worsen any failures?*
This module clusters both sides, matches signatures by template, and classifies
each into new / resolved / worsened / improved / unchanged — deterministically,
no LLM.
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

from .clustering import Cluster
from .parser import Severity


@dataclass(frozen=True)
class ClusterDelta:
    """How one signature changed between the two logs."""

    template: str
    level: Severity | None
    before: int
    after: int
    status: str  # new | resolved | worsened | improved | unchanged

    @property
    def delta(self) -> int:
        return self.after - self.before


@dataclass(frozen=True)
class DiffReport:
    deltas: tuple[ClusterDelta, ...]

    def by_status(self, status: str) -> list[ClusterDelta]:
        return [d for d in self.deltas if d.status == status]


def _classify(before: int, after: int) -> str:
    if before == 0 and after > 0:
        return "new"
    if after == 0 and before > 0:
        return "resolved"
    if after > before:
        return "worsened"
    if after < before:
        return "improved"
    return "unchanged"


def diff_clusters(before: list[Cluster], after: list[Cluster]) -> DiffReport:
    """Match clusters by template across two logs and classify each change."""

    before_map = {c.template: c for c in before}
    after_map = {c.template: c for c in after}
    templates = sorted(set(before_map) | set(after_map))

    deltas: list[ClusterDelta] = []
    for template in templates:
        b = before_map.get(template)
        a = after_map.get(template)
        b_count = b.count if b else 0
        a_count = a.count if a else 0
        level = (a.level if a else None) or (b.level if b else None)
        deltas.append(
            ClusterDelta(
                template=template,
                level=level,
                before=b_count,
                after=a_count,
                status=_classify(b_count, a_count),
            )
        )
    # Most actionable first: new and worsened, by magnitude of change.
    rank = {"new": 0, "worsened": 1, "improved": 2, "resolved": 3, "unchanged": 4}
    deltas.sort(key=lambda d: (rank[d.status], -abs(d.delta)))
    return DiffReport(deltas=tuple(deltas))


_STATUS_STYLE = {
    "new": "bold red",
    "worsened": "red",
    "improved": "green",
    "resolved": "bold green",
    "unchanged": "dim",
}


def render_diff(report: DiffReport, console: Console, show_unchanged: bool = False) -> None:
    """Render the diff as a colored table, most actionable rows first."""

    counts = {s: len(report.by_status(s)) for s in _STATUS_STYLE}
    console.print(
        f"[bold]Signature diff[/bold] · "
        f"[red]{counts['new']} new[/red] · [red]{counts['worsened']} worse[/red] · "
        f"[green]{counts['improved']} better[/green] · "
        f"[green]{counts['resolved']} resolved[/green] · {counts['unchanged']} unchanged\n"
    )
    table = Table(expand=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Lvl", no_wrap=True)
    table.add_column("Before", justify="right", no_wrap=True)
    table.add_column("After", justify="right", no_wrap=True)
    table.add_column("Signature", overflow="fold")
    for d in report.deltas:
        if d.status == "unchanged" and not show_unchanged:
            continue
        style = _STATUS_STYLE[d.status]
        table.add_row(
            f"[{style}]{d.status}[/{style}]",
            d.level.name[:4] if d.level else "?",
            str(d.before),
            str(d.after),
            d.template[:90],
        )
    console.print(table)
