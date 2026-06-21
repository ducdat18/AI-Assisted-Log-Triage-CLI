"""Push an incident summary to a webhook (Slack-compatible or generic JSON).

After triage, the natural next step is to *tell someone*. This exporter posts a
compact incident summary to an incoming webhook. Two shapes are supported:

* ``slack`` — a Slack/Mattermost ``{"text": ...}`` payload with markdown.
* ``generic`` — the structured report dict, for any JSON webhook receiver.

It depends only on ``requests`` (already a core dependency) and never sends log
*contents* beyond the report fields the user already chose to generate.
"""

from __future__ import annotations

import requests

from ..report import IncidentReport


class WebhookError(RuntimeError):
    """Raised when posting to a webhook fails."""


def build_slack_payload(report: IncidentReport, source: str) -> dict[str, object]:
    """A Slack incoming-webhook payload summarizing the incident."""

    text = (
        f"*:rotating_light: loglens incident — {source}*\n"
        f"_{report.total_errors} error/warning lines · {report.cluster_count} clusters · "
        f"{report.provider}/{report.model}_\n\n"
        f"*Summary*\n{report.summary}\n\n"
        f"*Root cause*\n{report.root_cause}\n\n"
        f"*Remediation*\n{report.remediation}"
    )
    return {"text": text}


def notify(
    report: IncidentReport,
    source: str,
    webhook_url: str,
    style: str = "slack",
    timeout: float = 15.0,
) -> None:
    """Post the incident report to ``webhook_url``.

    ``style`` is ``"slack"`` (a ``{"text": ...}`` markdown payload) or
    ``"generic"`` (the structured report dict). Raises :class:`WebhookError`
    on any transport or HTTP failure.
    """

    payload: dict[str, object] = (
        build_slack_payload(report, source) if style == "slack" else report.to_dict(source)
    )
    try:
        response = requests.post(webhook_url, json=payload, timeout=timeout)
    except requests.exceptions.ConnectionError as exc:
        raise WebhookError(f"Could not reach webhook at {webhook_url}.") from exc
    except requests.RequestException as exc:  # pragma: no cover - network
        raise WebhookError(f"Webhook request failed: {exc}") from exc
    if response.status_code >= 300:
        raise WebhookError(
            f"Webhook rejected the post (HTTP {response.status_code}): {response.text[:200]}"
        )
