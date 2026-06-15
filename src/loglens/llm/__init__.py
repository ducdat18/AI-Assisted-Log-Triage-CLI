"""Pluggable LLM backend for loglens.

The rest of the codebase depends only on the :class:`LLMProvider` abstraction,
never on a concrete vendor. Swapping Ollama for Gemini (or a future provider)
is a one-line factory change.
"""

from __future__ import annotations

from .base import LLMError, LLMProvider
from .factory import DEFAULT_PROVIDER, available_providers, get_provider

__all__ = [
    "LLMProvider",
    "LLMError",
    "get_provider",
    "available_providers",
    "DEFAULT_PROVIDER",
]
