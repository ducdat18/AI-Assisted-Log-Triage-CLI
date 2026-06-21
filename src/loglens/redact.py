"""PII / secret redaction applied before any text leaves the machine.

Responsible-AI guard rail: when ``--redact`` is enabled, every string sent to a
(potentially remote) LLM provider is scrubbed of common sensitive tokens. The
patterns are intentionally conservative — false positives (over-redaction) are
far cheaper than leaking a credential to a third-party API.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Order matters: more specific patterns run before broad ones so that, e.g.,
# a token inside a URL is masked as a token rather than a generic number.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    (
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    ),
    (
        "BEARER",
        re.compile(r"(?i)\b(bearer|token|authorization)\s*[:=]?\s*[A-Za-z0-9._\-]{12,}"),
    ),
    (
        "APIKEY",
        re.compile(r"(?i)\b(?:api[_-]?key|secret|password|passwd|pwd|access[_-]?key)\s*[:=]\s*\S+"),
    ),
    (
        "SECRET_PREFIX",
        re.compile(r"\b(?:sk|pk|ghp|gho|xox[baprs]|AKIA)[-_][A-Za-z0-9]{8,}\b"),
    ),
    (
        "CREDITCARD",
        re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    ),
    (
        "IPV6",
        re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b"),
    ),
    (
        "IPV4",
        re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    ),
)


@dataclass(frozen=True)
class RedactionResult:
    """Outcome of a redaction pass."""

    text: str
    counts: dict[str, int]

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def redact(text: str) -> RedactionResult:
    """Return ``text`` with sensitive tokens replaced by ``[REDACTED:<kind>]``."""

    counts: dict[str, int] = {}
    redacted = text
    for kind, pattern in _PATTERNS:

        def _replace(match: re.Match[str], _kind: str = kind) -> str:
            counts[_kind] = counts.get(_kind, 0) + 1
            return f"[REDACTED:{_kind}]"

        redacted = pattern.sub(_replace, redacted)
    return RedactionResult(text=redacted, counts=counts)


def redact_text(text: str) -> str:
    """Convenience wrapper returning only the scrubbed string."""

    return redact(text).text
