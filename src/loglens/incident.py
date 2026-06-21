"""Incident analytics: combine temporal + correlation analysis into findings.

This is the layer that makes loglens "more than an LLM call". It runs the
deterministic :mod:`loglens.anomaly` and :mod:`loglens.correlation` analyses and
turns them into three things:

* :func:`analyze_incident` — the structured :class:`IncidentFindings`.
* :func:`evidence_block` — a compact, factual text block the LLM is *grounded*
  on, so its narrative cites a computed timeline instead of guessing one.
* :func:`deterministic_report` — a full incident report built purely from the
  findings, with **no model involved at all** (the ``--no-llm`` path).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from .anomaly import AnomalyReport, BaselineModel, detect_anomalies
from .clustering import Cluster
from .correlation import CorrelationReport, correlate_clusters
from .parser import LogEntry
from .report import IncidentReport
from .scoring import confidence_label


@dataclass(frozen=True)
class IncidentFindings:
    """Deterministic analysis results for one log, independent of any LLM."""

    anomaly: AnomalyReport
    correlation: CorrelationReport
    bucket_seconds: int


def analyze_incident(
    entries: list[LogEntry],
    clusters: list[Cluster],
    baseline: BaselineModel | None = None,
) -> IncidentFindings:
    """Run temporal + correlation analysis over ranked ``clusters``.

    When ``baseline`` (learned from a healthy log) is given, anomaly detection
    scores against that seasonal expectation instead of the log's own history.
    """

    anomaly = detect_anomalies(entries, clusters=clusters, baseline=baseline)
    correlation = correlate_clusters(clusters, bucket_seconds=anomaly.bucket_seconds)
    return IncidentFindings(
        anomaly=anomaly,
        correlation=correlation,
        bucket_seconds=anomaly.bucket_seconds,
    )


def _fmt_time(ts: datetime | None) -> str:
    return ts.strftime("%H:%M:%S") if ts else "--:--:--"


def evidence_block(findings: IncidentFindings) -> str:
    """A factual, computed summary the LLM should base its narrative on."""

    a = findings.anomaly
    c = findings.correlation
    lines: list[str] = ["--- COMPUTED EVIDENCE (deterministic, trust this over guesses) ---"]
    lines.append(f"Time-bucket width: {a.bucket_seconds}s")
    if a.onset is not None:
        lines.append(
            f"Incident onset (first error spike): {a.onset.isoformat()} "
            f"(baseline ~{a.baseline_errors} errors/bucket, peak {a.peak_errors}; "
            f"confidence {a.onset_confidence:.2f} {confidence_label(a.onset_confidence)})"
        )
    else:
        lines.append("No clear error spike detected (errors evenly distributed).")

    if a.spikes:
        spike_desc = ", ".join(
            f"{_fmt_time(s.start)} ({s.errors} err, z={s.zscore:.1f})" for s in a.spikes[:5]
        )
        lines.append(f"Error spikes: {spike_desc}")

    if c.trigger is not None:
        trig = c.timeline[c.trigger]
        lines.append(
            f"Likely trigger (earliest severe cause): "
            f"{trig.template} @ {_fmt_time(trig.first_seen)} "
            f"(confidence {c.trigger_confidence:.2f} {confidence_label(c.trigger_confidence)})"
        )

    if c.has_cascade:
        lines.append("Inferred cascade (cause -> effect, lag, confidence):")
        for link in c.links[:8]:
            cause, effect = c.timeline[link.cause], c.timeline[link.effect]
            lines.append(
                f"  {cause.template[:60]} -> {effect.template[:60]} "
                f"(+{link.lag_seconds:.0f}s, overlap={link.jaccard}, conf={link.confidence})"
            )

    if a.bursts:
        lines.append("Bursty clusters (events concentrated, not steady):")
        for b in a.bursts[:5]:
            lines.append(
                f"  [{b.level.name if b.level else '?'}] {b.template[:60]} "
                f"— {b.peak_count}/{b.count} within one bucket ({b.concentration:.0%})"
            )
    return "\n".join(lines)


def _affected_components(findings: IncidentFindings) -> list[str]:
    """Components ordered by first appearance on the timeline."""

    seen: list[str] = []
    for event in findings.correlation.timeline:
        comp = event.component or "(uncomponented)"
        if comp not in seen:
            seen.append(comp)
    return seen


def deterministic_report(
    findings: IncidentFindings,
    clusters: list[Cluster],
    source: str,
) -> IncidentReport:
    """Build a complete incident report from findings alone — no LLM.

    The narrative is templated from computed facts: onset time, error-rate
    change, the inferred trigger, the cascade chain, and affected components.
    Less fluent than an LLM, but fully reproducible and always available.
    """

    a = findings.anomaly
    c = findings.correlation
    components = _affected_components(findings)

    # Summary.
    if a.onset is not None:
        window = f"starting {_fmt_time(a.onset)}"
        rate = f"error rate rose from ~{a.baseline_errors} to a peak of {a.peak_errors} per {a.bucket_seconds}s window"
    else:
        window = "across the captured window"
        rate = f"errors stayed near ~{a.baseline_errors} per {a.bucket_seconds}s window with no clear spike"
    n_spikes = len(a.spikes)
    summary = (
        f"An incident was detected {window}: {rate}. "
        f"{n_spikes} error spike(s) and {len(a.bursts)} bursty failure signature(s) were found "
        f"across {len(components)} component(s). "
    )
    if c.trigger is not None:
        trig = c.timeline[c.trigger]
        n_effects = sum(1 for link in c.links if link.cause == c.trigger)
        summary += (
            f"The earliest severe failure was in [{trig.component or '?'}] "
            f"and preceded {n_effects} downstream failure(s)."
        )

    # Root cause.
    if c.trigger is not None:
        trig = c.timeline[c.trigger]
        chain = _cascade_chain_text(c)
        root_cause = (
            f"Most likely origin: {trig.template} "
            f"(first seen {_fmt_time(trig.first_seen)}, {trig.count} occurrence(s); "
            f"confidence {c.trigger_confidence:.2f} {confidence_label(c.trigger_confidence)}). "
        )
        if chain:
            root_cause += f"Observed propagation: {chain}."
    else:
        root_cause = (
            "No single trigger could be isolated from timing alone; review the top clusters below."
        )

    # Affected components (ordered by first appearance).
    affected = "\n".join(f"- {comp}" for comp in components) or "- (none identified)"

    # Remediation — templated, anchored on the computed trigger and onset.
    remediation = _remediation_steps(findings)

    return IncidentReport(
        summary=summary,
        root_cause=root_cause,
        affected_components=affected,
        remediation=remediation,
        provider="deterministic",
        model="loglens-analytics",
        cluster_count=len(clusters),
        total_errors=sum(cl.count for cl in clusters),
        generated_at=datetime.now(),
        raw=evidence_block(findings),
    )


def _cascade_chain_text(c: CorrelationReport) -> str:
    """Render the longest cause->effect path through the cascade as text."""

    if not c.has_cascade:
        return ""
    # Follow links greedily from the trigger to build a readable chain.
    by_cause: dict[int, list] = {}
    for link in c.links:
        by_cause.setdefault(link.cause, []).append(link)
    start = c.trigger if c.trigger is not None else c.links[0].cause
    chain_nodes = [start]
    current = start
    visited = {start}
    while current in by_cause:
        nxt = max(by_cause[current], key=lambda link: link.jaccard).effect
        if nxt in visited:
            break
        chain_nodes.append(nxt)
        visited.add(nxt)
        current = nxt
    parts = [f"[{c.timeline[i].component or '?'}]" for i in chain_nodes]
    return " -> ".join(parts)


def _remediation_steps(findings: IncidentFindings) -> str:
    """Generate concrete next steps anchored on the computed findings."""

    a = findings.anomaly
    c = findings.correlation
    steps: list[str] = []
    if c.trigger is not None:
        trig = c.timeline[c.trigger]
        steps.append(
            f"Investigate [{trig.component or 'the trigger component'}] first — it is the "
            f"earliest severe failure and the head of the cascade."
        )
    if a.onset is not None:
        steps.append(
            f"Correlate deploys/config changes around {_fmt_time(a.onset)}, the detected onset."
        )
    if a.bursts:
        b = a.bursts[0]
        steps.append(
            f"Add rate-based alerting on '{b.template[:50]}' — it burst to "
            f"{b.peak_count} events in one {a.bucket_seconds}s window."
        )
    steps.append(
        "Add alerting on the error-rate baseline deviation so this onset is caught automatically next time."
    )
    return "\n".join(f"{i}. {s}" for i, s in enumerate(steps, start=1))


def render_findings(findings: IncidentFindings, console: Console) -> None:
    """Print the deterministic timeline + anomalies to the terminal."""

    a = findings.anomaly
    c = findings.correlation

    if a.onset is not None:
        console.print(
            f"[bold]Onset[/bold] {_fmt_time(a.onset)} "
            f"[dim](conf {a.onset_confidence:.2f} · {confidence_label(a.onset_confidence)})[/dim] · "
            f"baseline ~{a.baseline_errors} -> peak {a.peak_errors} errors/"
            f"{a.bucket_seconds}s · {len(a.spikes)} spike(s)\n"
        )

    if c.timeline:
        table = Table(title="Incident timeline (by first appearance)", expand=True)
        table.add_column("Time", no_wrap=True)
        table.add_column("Lvl", no_wrap=True)
        table.add_column("Comp", no_wrap=True)
        table.add_column("Signature", overflow="fold")
        for event in c.timeline:
            marker = " *" if event.order == c.trigger else ""
            level = event.level.name[:4] if event.level else "?"
            table.add_row(
                _fmt_time(event.first_seen),
                f"[bold]{level}[/bold]{marker}",
                event.component or "?",
                escape(event.template[:90]),
            )
        console.print(table)

    if c.has_cascade:
        console.print("\n[bold]Inferred cascade[/bold]")
        for link in c.links[:8]:
            cause, effect = c.timeline[link.cause], c.timeline[link.effect]
            console.print(
                f"  [cyan]{escape(cause.component or '?')}[/cyan] -> "
                f"[magenta]{escape(effect.component or '?')}[/magenta] "
                f"[dim](+{link.lag_seconds:.0f}s, overlap={link.jaccard}, "
                f"conf {link.confidence:.2f})[/dim]"
            )
