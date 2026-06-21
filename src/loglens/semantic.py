"""Semantic clustering merge — fold near-duplicate templates together.

Regex and Drain both cluster by *surface* structure, so they split messages that
mean the same thing but read differently: "DB connection refused" and "could not
connect to database" stay apart. This module embeds each cluster's template into
a vector and merges clusters whose embeddings are close, collapsing those
synonym-splits into one signature.

The embedding backend is pluggable, mirroring the LLM layer:

* :class:`TfidfEmbedder` — a pure-Python TF-IDF vectorizer (default). No network,
  fully deterministic, good enough to catch token-overlap synonyms.
* :class:`OllamaEmbedder` — calls a local Ollama embeddings model for true
  semantic similarity, still local and free.

``merge_similar`` is the entry point; it returns a fresh, re-rankable cluster
list and never mutates its input.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Protocol

from .clustering import Cluster, rank_clusters

_TOKEN_RE = re.compile(r"[A-Za-z]+")


class Embedder(Protocol):
    """Anything that can turn texts into comparable vectors."""

    def embed(self, texts: list[str]) -> list[list[float]]: ...


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


class TfidfEmbedder:
    """Deterministic pure-Python TF-IDF vectorizer over a shared vocabulary."""

    def embed(self, texts: list[str]) -> list[list[float]]:
        docs = [_tokenize(t) for t in texts]
        vocab: dict[str, int] = {}
        for doc in docs:
            for tok in doc:
                vocab.setdefault(tok, len(vocab))
        if not vocab:
            return [[0.0] for _ in texts]

        n_docs = len(docs)
        df = Counter(tok for doc in docs for tok in set(doc))
        idf = {tok: math.log((n_docs + 1) / (df[tok] + 1)) + 1.0 for tok in vocab}

        vectors: list[list[float]] = []
        for doc in docs:
            counts = Counter(doc)
            length = len(doc) or 1
            vec = [0.0] * len(vocab)
            for tok, count in counts.items():
                vec[vocab[tok]] = (count / length) * idf[tok]
            vectors.append(vec)
        return vectors


class OllamaEmbedder:
    """Embeddings from a local Ollama model (no data leaves the machine)."""

    def __init__(
        self,
        model: str = "nomic-embed-text",
        host: str = "http://localhost:11434",
        timeout: float = 60.0,
    ) -> None:
        self.model = model
        self.host = host.rstrip("/")
        self.timeout = timeout

    def embed(self, texts: list[str]) -> list[list[float]]:
        import requests  # local import: only needed on this optional path

        out: list[list[float]] = []
        for text in texts:
            resp = requests.post(
                f"{self.host}/api/embeddings",
                json={"model": self.model, "prompt": text},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            out.append(resp.json()["embedding"])
        return out


def get_embedder(name: str = "tfidf") -> Embedder:
    """Resolve an embedder by name: ``"tfidf"`` (default) or ``"ollama"``."""

    if name == "ollama":
        return OllamaEmbedder()
    return TfidfEmbedder()


def cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity of two equal-length vectors, in [-1, 1]."""

    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na < 1e-12 or nb < 1e-12:
        return 0.0
    return dot / (na * nb)


def _merge_two(primary: Cluster, other: Cluster) -> Cluster:
    """Fold ``other`` into ``primary``, keeping the more severe/representative one."""

    keep, fold = (primary, other) if primary.count >= other.count else (other, primary)
    level = keep.level
    if fold.level is not None and (level is None or fold.level > level):
        level = fold.level
    merged = Cluster(template=keep.template, level=level)
    merged.entries = keep.entries + fold.entries
    return merged


def merge_similar(
    clusters: list[Cluster],
    threshold: float = 0.85,
    embedder: Embedder | None = None,
) -> list[Cluster]:
    """Merge clusters whose template embeddings exceed ``threshold`` cosine.

    Uses a union-find over the pairwise similarity graph so transitively-similar
    clusters end up in one group. Returns a new, re-ranked cluster list; the
    input is left untouched.
    """

    if len(clusters) < 2:
        return list(clusters)
    embedder = embedder or get_embedder()
    vectors = embedder.embed([c.template for c in clusters])

    parent = list(range(len(clusters)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        parent[find(i)] = find(j)

    for i in range(len(clusters)):
        for j in range(i + 1, len(clusters)):
            if cosine(vectors[i], vectors[j]) >= threshold:
                union(i, j)

    groups: dict[int, list[int]] = {}
    for i in range(len(clusters)):
        groups.setdefault(find(i), []).append(i)

    merged: list[Cluster] = []
    for members in groups.values():
        cluster = clusters[members[0]]
        for idx in members[1:]:
            cluster = _merge_two(cluster, clusters[idx])
        merged.append(cluster)
    return rank_clusters(merged)
