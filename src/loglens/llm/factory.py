"""Provider selection: ``--provider`` flag > ``LOGLENS_PROVIDER`` env > default."""

from __future__ import annotations

import os
from collections.abc import Callable

from .base import LLMError, LLMProvider
from .providers.gemini import GeminiProvider
from .providers.ollama import OllamaProvider

DEFAULT_PROVIDER = "ollama"

# Registry maps a provider name to a zero-arg-friendly constructor. A custom
# model overrides the provider default when supplied.
_REGISTRY: dict[str, Callable[..., LLMProvider]] = {
    "ollama": OllamaProvider,
    "gemini": GeminiProvider,
}


def available_providers() -> list[str]:
    """Names of all registered providers."""

    return sorted(_REGISTRY)


def resolve_provider_name(explicit: str | None = None) -> str:
    """Resolve the effective provider name from flag, env, then default."""

    name = (explicit or os.environ.get("LOGLENS_PROVIDER") or DEFAULT_PROVIDER).lower()
    if name not in _REGISTRY:
        raise LLMError(f"Unknown provider '{name}'. Available: {', '.join(available_providers())}.")
    return name


def get_provider(
    name: str | None = None,
    model: str | None = None,
    timeout: float = 120.0,
) -> LLMProvider:
    """Instantiate the configured provider.

    ``name`` may be ``None`` to fall back to ``LOGLENS_PROVIDER`` / the default.
    ``model`` overrides the provider's built-in default model when given.
    """

    resolved = resolve_provider_name(name)
    factory = _REGISTRY[resolved]
    kwargs: dict[str, object] = {"timeout": timeout}
    if model:
        kwargs["model"] = model
    return factory(**kwargs)
