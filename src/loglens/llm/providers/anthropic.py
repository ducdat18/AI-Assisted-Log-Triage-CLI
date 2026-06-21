"""Anthropic Claude provider (hosted).

Uses the Anthropic Messages API. The API key is read from ``ANTHROPIC_API_KEY``;
nothing is hardcoded. As with any remote backend, pair with ``--redact`` when log
data may contain sensitive content.
"""

from __future__ import annotations

import json
import os

import requests

from ..base import LLMError, LLMProvider

DEFAULT_MODEL = "claude-haiku-4-5-20251001"
_API_URL = "https://api.anthropic.com/v1/messages"
_API_VERSION = "2023-06-01"


class AnthropicProvider(LLMProvider):
    """Generate completions via Anthropic's Messages API."""

    name = "anthropic"

    def __init__(self, model: str = DEFAULT_MODEL, timeout: float = 120.0) -> None:
        super().__init__(model=model, timeout=timeout)
        self._api_key = os.environ.get("ANTHROPIC_API_KEY")

    def generate(self, prompt: str, system: str | None = None) -> str:
        if not self._api_key:
            raise LLMError(
                "Anthropic API key not set. Export ANTHROPIC_API_KEY to use "
                "--provider anthropic."
            )
        payload: dict[str, object] = {
            "model": self.model,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            payload["system"] = system
        try:
            response = requests.post(
                _API_URL,
                headers={
                    "x-api-key": self._api_key,
                    "anthropic-version": _API_VERSION,
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=self.timeout,
            )
        except requests.exceptions.ConnectionError as exc:
            raise LLMError("Could not reach the Anthropic API.") from exc
        except requests.RequestException as exc:  # pragma: no cover - network
            raise LLMError(f"Anthropic request failed: {exc}") from exc

        if response.status_code >= 400:
            raise LLMError(f"Anthropic returned HTTP {response.status_code}: {response.text[:200]}")
        try:
            data = response.json()
            text = data["content"][0]["text"]
        except (json.JSONDecodeError, KeyError, IndexError) as exc:  # pragma: no cover
            raise LLMError("Anthropic returned an unexpected response shape.") from exc
        if not text:
            raise LLMError("Anthropic returned an empty response.")
        return str(text).strip()
