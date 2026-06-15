"""Tests for report generation and hierarchical summarization with a mocked LLM."""

from __future__ import annotations

from loglens.clustering import cluster_and_rank
from loglens.llm import LLMError, get_provider
from loglens.llm.base import LLMProvider
from loglens.parser import LogEntry, Severity
from loglens.report import generate_report
from loglens.summarize import build_context, estimate_tokens


class MockProvider(LLMProvider):
    """Records prompts and returns a canned, contract-shaped response."""

    name = "mock"

    def __init__(self) -> None:
        super().__init__(model="mock-1")
        self.prompts: list[str] = []
        self.response = (
            "SUMMARY:\n"
            "The database primary became unreachable, cascading into checkout failures.\n\n"
            "ROOT_CAUSE:\n"
            "Connection pool exhaustion against the primary DB.\n\n"
            "AFFECTED_COMPONENTS:\n"
            "- payments-svc\n- checkout\n\n"
            "REMEDIATION:\n"
            "1. Fail over to a replica.\n2. Increase pool size.\n"
        )

    def generate(self, prompt: str, system: str | None = None) -> str:
        self.prompts.append(prompt)
        return self.response


def _error_entries(n: int) -> list[LogEntry]:
    return [
        LogEntry(line_no=i, raw="db boom", message=f"Database query failed pool timeout {i}",
                 level=Severity.ERROR)
        for i in range(n)
    ]


def test_generate_report_parses_sections():
    clusters = cluster_and_rank(_error_entries(5))
    provider = MockProvider()
    report = generate_report(clusters, provider, source="test.log")

    assert "database primary" in report.summary.lower()
    assert "pool exhaustion" in report.root_cause.lower()
    assert "payments-svc" in report.affected_components
    assert report.remediation.startswith("1.")
    assert report.provider == "mock"
    assert report.total_errors == 5


def test_report_markdown_contains_all_sections():
    clusters = cluster_and_rank(_error_entries(3))
    report = generate_report(clusters, MockProvider(), source="api.log")
    md = report.to_markdown("api.log")
    for header in ("# Incident Report", "## Summary", "## Most Likely Root Cause",
                   "## Affected Components", "## Remediation Steps"):
        assert header in md


def test_report_falls_back_when_headers_missing():
    class BlobProvider(MockProvider):
        def generate(self, prompt: str, system: str | None = None) -> str:
            return "just an unstructured wall of text"

    clusters = cluster_and_rank(_error_entries(2))
    report = generate_report(clusters, BlobProvider(), source="x.log")
    assert "unstructured wall" in report.summary
    assert report.root_cause == "(not provided by model)"


def test_build_context_returns_verbatim_when_small():
    clusters = cluster_and_rank(_error_entries(2))
    provider = MockProvider()
    context = build_context(clusters, provider, token_budget=10000)
    # Small input: no summarization calls were needed.
    assert provider.prompts == []
    assert "Database query failed" in context


def _alpha(i: int) -> str:
    """Encode an index as a distinct lowercase word (no digits to be masked)."""

    word, i = "", i + 1
    while i:
        i, rem = divmod(i - 1, 26)
        word = chr(97 + rem) + word
    return word


def test_build_context_triggers_hierarchical_summarization():
    # Many *distinct* clusters (alphabetic, so normalization keeps them apart)
    # force the digest over a tiny budget and trigger map-reduce summarization.
    entries = [
        LogEntry(line_no=i, raw="e", message=f"subsystem {_alpha(i)} crashed unexpectedly",
                 level=Severity.ERROR)
        for i in range(40)
    ]
    clusters = cluster_and_rank(entries)
    provider = MockProvider()
    context = build_context(clusters, provider, token_budget=200)
    # Over budget: the provider was invoked to reduce batches.
    assert provider.prompts, "expected summarization calls"
    assert estimate_tokens(context) <= 200 or "Batch" in context


def test_redaction_applied_in_context():
    entries = [
        LogEntry(line_no=1, raw="x", message="login failed for admin@corp.com",
                 level=Severity.ERROR),
    ]
    clusters = cluster_and_rank(entries)
    context = build_context(clusters, MockProvider(), redact=True, token_budget=10000)
    assert "admin@corp.com" not in context
    assert "[REDACTED:EMAIL]" in context


def test_factory_unknown_provider_raises():
    try:
        get_provider("nope")
    except LLMError as exc:
        assert "Unknown provider" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected LLMError")


def test_factory_default_is_ollama():
    provider = get_provider()
    assert provider.name == "ollama"


def test_factory_model_override():
    provider = get_provider("ollama", model="custom-model")
    assert provider.model == "custom-model"
