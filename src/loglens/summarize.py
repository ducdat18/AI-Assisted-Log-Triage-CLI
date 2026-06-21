"""Token-aware context building and hierarchical summarization.

Large incidents produce more clusters than fit in a model's context window. We
estimate token cost cheaply (no tokenizer dependency) and, when the cluster
digest is too big, summarize batches of clusters first, then summarize the
batch summaries — a classic map-reduce / hierarchical reduction that keeps the
final prompt within budget.
"""

from __future__ import annotations

from dataclasses import dataclass

from .clustering import Cluster
from .llm import LLMProvider
from .redact import redact_text

# Rough heuristic: ~4 characters per token for English + code. Good enough for
# budgeting without pulling in a model-specific tokenizer.
_CHARS_PER_TOKEN = 4


def estimate_tokens(text: str) -> int:
    """Cheap, dependency-free token estimate."""

    return max(1, len(text) // _CHARS_PER_TOKEN)


@dataclass(frozen=True)
class ClusterDigest:
    """Compact, model-ready text describing one cluster."""

    text: str
    tokens: int


def _cluster_to_text(cluster: Cluster, redact: bool) -> str:
    level = cluster.level.name if cluster.level else "UNKNOWN"
    sample = cluster.representative.message
    template = cluster.template
    if redact:
        # Scrub both the example and the template — the template is derived
        # from a raw message and may still carry PII the masking rules miss.
        sample = redact_text(sample)
        template = redact_text(template)
    span = ""
    if cluster.first_seen and cluster.last_seen:
        span = f" | window {cluster.first_seen.isoformat()} → {cluster.last_seen.isoformat()}"
    return f"[{level} x{cluster.count}]{span}\n" f"  template: {template}\n" f"  example:  {sample}"


def build_digests(clusters: list[Cluster], redact: bool = False) -> list[ClusterDigest]:
    """Turn clusters into per-cluster digest blocks with token estimates."""

    digests: list[ClusterDigest] = []
    for cluster in clusters:
        text = _cluster_to_text(cluster, redact)
        digests.append(ClusterDigest(text=text, tokens=estimate_tokens(text)))
    return digests


def _pack(digests: list[ClusterDigest], budget: int) -> list[list[ClusterDigest]]:
    """Greedily pack digests into batches that each fit within ``budget``."""

    batches: list[list[ClusterDigest]] = []
    current: list[ClusterDigest] = []
    used = 0
    for digest in digests:
        if current and used + digest.tokens > budget:
            batches.append(current)
            current, used = [], 0
        current.append(digest)
        used += digest.tokens
    if current:
        batches.append(current)
    return batches


_REDUCE_SYSTEM = (
    "You are a log-analysis assistant. Condense the provided log error clusters "
    "into a terse factual summary of distinct failure modes, their severity and "
    "frequency. Preserve concrete error signatures. Do not speculate yet."
)


def build_context(
    clusters: list[Cluster],
    provider: LLMProvider,
    redact: bool = False,
    token_budget: int = 6000,
) -> str:
    """Build an LLM-ready context block that fits within ``token_budget``.

    If the raw digests already fit, they are returned verbatim. Otherwise the
    digests are batched, each batch is summarized by ``provider``, and the
    intermediate summaries are concatenated (recursively reduced if still too
    large).
    """

    digests = build_digests(clusters, redact=redact)
    joined = "\n\n".join(d.text for d in digests)
    if estimate_tokens(joined) <= token_budget:
        return joined

    # Reserve headroom so intermediate summaries themselves stay well under budget.
    batch_budget = max(1000, token_budget // 2)
    batches = _pack(digests, batch_budget)
    summaries: list[str] = []
    for index, batch in enumerate(batches, start=1):
        batch_text = "\n\n".join(d.text for d in batch)
        prompt = (
            f"Summarize this batch ({index}/{len(batches)}) of log error "
            f"clusters:\n\n{batch_text}"
        )
        summaries.append(provider.generate(prompt, system=_REDUCE_SYSTEM))

    reduced = "\n\n".join(f"## Batch {i}\n{s}" for i, s in enumerate(summaries, start=1))
    if estimate_tokens(reduced) <= token_budget:
        return reduced

    # Still too large: reduce once more over the summaries themselves.
    prompt = f"Further condense these batch summaries into one:\n\n{reduced}"
    return provider.generate(prompt, system=_REDUCE_SYSTEM)
