"""Abstract LLM provider interface.

Every backend implements :meth:`LLMProvider.generate`. The interface is kept
minimal on purpose — a single text-in/text-out call — so that new providers
(local or hosted) are trivial to add without touching the analysis pipeline.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class LLMError(RuntimeError):
    """Raised when a provider cannot fulfil a generation request.

    Carries a human-readable message suitable for surfacing in the CLI; the
    original cause (network error, HTTP status, etc.) is chained via ``raise
    ... from``.
    """


class LLMProvider(ABC):
    """Text-completion backend abstraction."""

    #: Short, stable identifier used by the factory and ``--provider`` flag.
    name: str = "base"

    def __init__(self, model: str, timeout: float = 120.0) -> None:
        self.model = model
        self.timeout = timeout

    @abstractmethod
    def generate(self, prompt: str, system: str | None = None) -> str:
        """Return the model's completion for ``prompt``.

        ``system`` is an optional system / instruction prompt. Implementations
        must raise :class:`LLMError` (never a bare network exception) on
        failure so callers can handle it uniformly.
        """

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"{type(self).__name__}(model={self.model!r})"
