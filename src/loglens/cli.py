"""loglens command-line interface (Typer + Rich)."""

from __future__ import annotations

import time
from pathlib import Path

import typer
from rich.console import Console

from . import __version__
from .anomaly import detect_anomalies, learn_baseline
from .clustering import cluster_and_rank, normalize
from .diff import diff_clusters, render_diff
from .exporters import (
    DEFAULT_LOKI_URL,
    LokiClient,
    LokiError,
    WebhookError,
    build_streams,
    notify,
)
from .incident import (
    analyze_incident,
    deterministic_report,
    evidence_block,
    render_findings,
)
from .llm import LLMError, available_providers, get_provider
from .parser import Severity, parse_file, parse_line, parse_lines
from .redact import redact
from .report import generate_report, render_clusters_table, render_report, write_report
from .semantic import merge_similar
from .severity_infer import apply_inference

app = typer.Typer(
    add_completion=False,
    help="AI-assisted log triage for operational and incident diagnostics.",
)
console = Console()
err_console = Console(stderr=True)


def _maybe_notify(report, source: str, webhook: str | None, style: str) -> None:
    """Post the report to a webhook if one was configured; warn on failure."""

    if not webhook:
        return
    try:
        notify(report, source, webhook, style=style)
        console.print(f"[green]Notified webhook[/green] ({style}).")
    except WebhookError as exc:
        err_console.print(f"[yellow]Webhook notification failed:[/yellow] {exc}")


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"loglens {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """loglens — turn noisy logs into an actionable incident report."""


@app.command()
def analyze(
    logfile: Path = typer.Argument(..., exists=True, readable=True, help="Log file to analyze."),
    provider: str | None = typer.Option(
        None,
        "--provider",
        "-p",
        help=f"LLM backend ({', '.join(available_providers())}). "
        "Defaults to $LOGLENS_PROVIDER or 'ollama'.",
    ),
    model: str | None = typer.Option(None, "--model", "-m", help="Override the model name."),
    fmt: str | None = typer.Option(
        None,
        "--format",
        "-f",
        help="Force log format: 'text' or 'json' (auto-detected by default).",
    ),
    top: int = typer.Option(
        8, "--top", "-n", min=1, help="Number of top clusters to send to the LLM."
    ),
    min_level: str = typer.Option(
        "WARNING",
        "--min-level",
        "-l",
        help="Minimum severity to include (TRACE/DEBUG/INFO/WARNING/ERROR/CRITICAL).",
    ),
    redact_flag: bool = typer.Option(
        False,
        "--redact",
        help="Strip PII/secrets before sending anything to the LLM.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the report to this path; format is chosen by extension "
        "(.md / .html / .json).",
    ),
    json_out: bool = typer.Option(
        False,
        "--json",
        help="Print the report as JSON to stdout (machine-readable; implies no panels).",
    ),
    token_budget: int = typer.Option(
        6000,
        "--token-budget",
        help="Approx. token budget for LLM context (triggers hierarchical summarization).",
    ),
    no_llm: bool = typer.Option(
        False,
        "--no-llm",
        help="Skip the LLM entirely: build the report from deterministic analytics only.",
    ),
    drain: bool = typer.Option(
        False,
        "--drain",
        help="Cluster with the Drain template miner instead of regex templates.",
    ),
    baseline: Path | None = typer.Option(
        None,
        "--baseline",
        help="A healthy log to learn the expected (seasonal) error rate from, so "
        "the incident is scored against expectation rather than its own history.",
    ),
    semantic: bool = typer.Option(
        False,
        "--semantic",
        help="Merge near-duplicate clusters by embedding similarity (folds "
        "synonym-split errors together). Local/offline TF-IDF by default.",
    ),
    infer_severity: bool = typer.Option(
        False,
        "--infer-severity",
        help="Infer a severity for log lines that have no explicit level, from "
        "their text, so unlabeled error lines are not missed by triage.",
    ),
    webhook: str | None = typer.Option(
        None,
        "--webhook",
        help="Post the incident summary to this webhook URL when done.",
    ),
    notify_style: str = typer.Option(
        "slack",
        "--notify-style",
        help="Webhook payload style: 'slack' (markdown) or 'generic' (JSON).",
    ),
) -> None:
    """Parse, cluster, and generate an incident report for LOGFILE."""

    threshold = Severity.from_text(min_level)
    if threshold is None:
        err_console.print(f"[red]Invalid --min-level '{min_level}'.[/red]")
        raise typer.Exit(code=2)

    with console.status("[cyan]Parsing log file…[/cyan]"):
        entries = parse_file(str(logfile), fmt=fmt)
    if not entries:
        err_console.print("[yellow]No log lines found.[/yellow]")
        raise typer.Exit(code=1)

    if infer_severity:
        entries, filled = apply_inference(entries)
        if filled:
            console.print(f"[dim]Inferred a severity for {filled} unlabeled line(s).[/dim]")

    baseline_model = None
    if baseline is not None:
        baseline_entries = parse_file(str(baseline), fmt=fmt)
        bucket_seconds = detect_anomalies(entries).bucket_seconds
        baseline_model = learn_baseline(baseline_entries, bucket_seconds)
        console.print(f"[dim]Learned seasonal baseline from {baseline.name}.[/dim]")

    method = "drain" if drain else "regex"
    if semantic:
        # Merge synonym-split clusters before taking the top N.
        full = cluster_and_rank(entries, min_level=threshold, method=method)
        clusters = merge_similar(full)[:top]
    else:
        clusters = cluster_and_rank(entries, top_n=top, min_level=threshold, method=method)
    if not clusters:
        console.print(
            f"[green]No entries at or above {threshold.name}. "
            f"Parsed {len(entries)} lines — nothing to triage.[/green]"
        )
        raise typer.Exit(code=0)

    total_matched = sum(c.count for c in clusters)
    if not json_out:
        console.print(
            f"[dim]Parsed {len(entries)} lines · {total_matched} at/above "
            f"{threshold.name} · {len(clusters)} clusters shown · clusterer={method}[/dim]\n"
        )
        render_clusters_table(clusters, console)

    # Deterministic analytics (onset, cascade, bursts) — runs with or without an LLM.
    findings = analyze_incident(entries, clusters, baseline=baseline_model)
    if not json_out:
        console.rule("[bold]Temporal & Cascade Analysis[/bold]")
        render_findings(findings, console)

    if no_llm:
        report = deterministic_report(findings, clusters, source=logfile.name)
        if json_out:
            print(report.to_json(logfile.name))
        else:
            console.rule("[bold]Incident Report[/bold] [dim](deterministic, no LLM)[/dim]")
            render_report(report, console)
        if output:
            fmt_written = write_report(report, str(output), logfile.name)
            console.print(f"\n[green]{fmt_written} report written to[/green] {output}")
        _maybe_notify(report, logfile.name, webhook, notify_style)
        return

    if redact_flag:
        console.print("[dim]Redaction enabled — scrubbing PII/secrets before LLM calls.[/dim]")

    backend = get_provider(provider, model=model)
    try:
        with console.status(f"[cyan]Triaging with {backend.name}/{backend.model}…[/cyan]"):
            report = generate_report(
                clusters,
                backend,
                source=logfile.name,
                redact=redact_flag,
                token_budget=token_budget,
                evidence=evidence_block(findings),
            )
    except LLMError as exc:
        err_console.print(f"\n[red]LLM error:[/red] {exc}")
        raise typer.Exit(code=3) from exc

    if json_out:
        print(report.to_json(logfile.name))
    else:
        console.rule("[bold]Incident Report[/bold]")
        render_report(report, console)

    if output:
        fmt_written = write_report(report, str(output), logfile.name)
        console.print(f"\n[green]{fmt_written} report written to[/green] {output}")
    _maybe_notify(report, logfile.name, webhook, notify_style)


@app.command()
def watch(
    logfile: Path = typer.Argument(..., exists=True, readable=True, help="Log file to tail."),
    fmt: str | None = typer.Option(
        None, "--format", "-f", help="Force log format: 'text' or 'json'."
    ),
    min_level: str = typer.Option(
        "ERROR",
        "--min-level",
        "-l",
        help="Minimum severity to surface while tailing.",
    ),
    redact_flag: bool = typer.Option(
        False, "--redact", help="Redact PII/secrets in surfaced lines."
    ),
    poll_interval: float = typer.Option(0.5, "--interval", help="Polling interval in seconds."),
) -> None:
    """Tail LOGFILE and surface anomalies (errors/warnings) in near-real-time."""

    threshold = Severity.from_text(min_level)
    if threshold is None:
        err_console.print(f"[red]Invalid --min-level '{min_level}'.[/red]")
        raise typer.Exit(code=2)

    resolved_fmt = fmt
    if resolved_fmt is None:
        with open(logfile, encoding="utf-8", errors="replace") as handle:
            head = [next(handle, "") for _ in range(20)]
        # Reuse the parser's detector via a full parse of the sample.
        resolved_fmt = (
            "json" if parse_lines(head) and head and head[0].strip().startswith("{") else "text"
        )

    console.print(
        f"[bold cyan]Watching[/bold cyan] {logfile} "
        f"(format={resolved_fmt}, min-level={threshold.name}). Press Ctrl+C to stop.\n"
    )

    severity_color = {
        Severity.CRITICAL: "bright_red",
        Severity.ERROR: "red",
        Severity.WARNING: "yellow",
        Severity.NOTICE: "cyan",
    }
    seen_templates: set[str] = set()
    line_no = 0
    try:
        with open(logfile, encoding="utf-8", errors="replace") as handle:
            handle.seek(0, 2)  # jump to end: only surface *new* lines
            while True:
                line = handle.readline()
                if not line:
                    time.sleep(poll_interval)
                    continue
                line_no += 1
                if not line.strip():
                    continue
                entry = parse_line(line_no, line, resolved_fmt)
                if entry.level is None or entry.level < threshold:
                    continue
                message = redact(entry.message).text if redact_flag else entry.message
                color = severity_color.get(entry.level, "white")
                template = normalize(entry.message)
                marker = "NEW " if template not in seen_templates else "    "
                seen_templates.add(template)
                ts = entry.timestamp.strftime("%H:%M:%S") if entry.timestamp else "--:--:--"
                console.print(
                    f"[dim]{ts}[/dim] [{color}]{marker}{entry.level.name:<8}[/{color}] {message}"
                )
    except KeyboardInterrupt:
        console.print("\n[dim]Stopped watching.[/dim]")


@app.command()
def ship(
    logfile: Path = typer.Argument(
        ..., exists=True, readable=True, help="Log file to ship to Loki."
    ),
    loki_url: str = typer.Option(
        DEFAULT_LOKI_URL,
        "--loki-url",
        "-u",
        help="Base URL of the Loki server.",
    ),
    source: str | None = typer.Option(
        None,
        "--source",
        "-s",
        help="Value for the 'source' label (defaults to the file name).",
    ),
    fmt: str | None = typer.Option(
        None, "--format", "-f", help="Force log format: 'text' or 'json'."
    ),
    min_level: str | None = typer.Option(
        None,
        "--min-level",
        "-l",
        help="Only ship entries at/above this severity (default: ship everything).",
    ),
    redact_flag: bool = typer.Option(
        False,
        "--redact",
        help="Strip PII/secrets from log lines before shipping.",
    ),
) -> None:
    """Ship LOGFILE to Grafana Loki, labelled by severity and error cluster.

    Each entry gets a stable ``cluster`` label so Grafana can collapse
    near-identical errors into a single series — group with
    ``sum by (cluster) (count_over_time({job="loglens"} [$__auto]))``.
    """

    with console.status("[cyan]Parsing log file…[/cyan]"):
        entries = parse_file(str(logfile), fmt=fmt)
    if not entries:
        err_console.print("[yellow]No log lines found.[/yellow]")
        raise typer.Exit(code=1)

    if min_level:
        threshold = Severity.from_text(min_level)
        if threshold is None:
            err_console.print(f"[red]Invalid --min-level '{min_level}'.[/red]")
            raise typer.Exit(code=2)
        entries = [e for e in entries if e.level is not None and e.level >= threshold]
        if not entries:
            console.print(f"[green]No entries at or above {threshold.name} to ship.[/green]")
            raise typer.Exit(code=0)

    streams = build_streams(entries, source=source or logfile.name, redact=redact_flag)
    client = LokiClient(loki_url)
    try:
        with console.status(f"[cyan]Pushing to Loki at {loki_url}…[/cyan]"):
            shipped = client.push(streams)
    except LokiError as exc:
        err_console.print(f"[red]Loki error:[/red] {exc}")
        raise typer.Exit(code=3) from exc

    console.print(
        f"[green]Shipped {shipped} entries[/green] across {len(streams)} streams "
        f"(label cluster count: {len({s['stream']['cluster'] for s in streams})}) to {loki_url}."
    )
    console.print(
        "[dim]In Grafana (Explore → Loki): " '{job="loglens"} | level=~"error|critical"[/dim]'
    )


@app.command()
def diff(
    before: Path = typer.Argument(
        ..., exists=True, readable=True, help="The earlier / baseline log."
    ),
    after: Path = typer.Argument(
        ..., exists=True, readable=True, help="The later log to compare against it."
    ),
    fmt: str | None = typer.Option(
        None, "--format", "-f", help="Force log format (default: auto-detect)."
    ),
    min_level: str = typer.Option(
        "WARNING", "--min-level", "-l", help="Minimum severity to include."
    ),
    drain: bool = typer.Option(False, "--drain", help="Cluster with the Drain template miner."),
    show_unchanged: bool = typer.Option(False, "--all", help="Also show unchanged signatures."),
) -> None:
    """Diff two logs by error signature: what's NEW, WORSE, BETTER, or RESOLVED."""

    threshold = Severity.from_text(min_level)
    if threshold is None:
        err_console.print(f"[red]Invalid --min-level '{min_level}'.[/red]")
        raise typer.Exit(code=2)

    method = "drain" if drain else "regex"
    with console.status("[cyan]Parsing and clustering both logs…[/cyan]"):
        before_clusters = cluster_and_rank(
            parse_file(str(before), fmt=fmt), min_level=threshold, method=method
        )
        after_clusters = cluster_and_rank(
            parse_file(str(after), fmt=fmt), min_level=threshold, method=method
        )

    report = diff_clusters(before_clusters, after_clusters)
    console.print(f"[dim]{before.name} -> {after.name}[/dim]\n")
    render_diff(report, console, show_unchanged=show_unchanged)


if __name__ == "__main__":  # pragma: no cover
    app()
