"""OpenAI-compatible providers: OpenAI and OpenRouter (hosted).

Both speak the same ``/chat/completions`` API, so a single implementation covers
them — only the base URL, API-key env var, and default model differ. Keys are
read from the environment; nothing is hardcoded. Pair with ``--redact`` when log
data may be sensitive, since these are remote services.
"""

from __future__ import annotations

import json
import os

import requests

from ..base import LLMError, LLMProvider


class OpenAICompatProvider(LLMProvider):
    """Base for any OpenAI ``/chat/completions``-compatible backend."""

    name = "openai-compat"
    base_url = "https://api.openai.com/v1"
    api_key_env = "OPENAI_API_KEY"
    default_model = "gpt-4o-mini"
    service_label = "OpenAI"

    def __init__(self, model: str | None = None, timeout: float = 120.0) -> None:
        super().__init__(model=model or self.default_model, timeout=timeout)
        self._api_key = os.environ.get(self.api_key_env)

    def generate(self, prompt: str, system: str | None = None) -> str:
        if not self._api_key:
            raise LLMError(
                f"{self.service_label} API key not set. "
                f"Export {self.api_key_env} to use --provider {self.name}."
            )
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json={"model": self.model, "messages": messages},
                timeout=self.timeout,
            )
        except requests.exceptions.ConnectionError as exc:
            raise LLMError(f"Could not reach {self.service_label} at {self.base_url}.") from exc
        except requests.RequestException as exc:  # pragma: no cover - network
            raise LLMError(f"{self.service_label} request failed: {exc}") from exc

        if response.status_code >= 400:
            raise LLMError(
                f"{self.service_label} returned HTTP {response.status_code}: "
                f"{response.text[:200]}"
            )
        try:
            data = response.json()
            text = data["choices"][0]["message"]["content"]
        except (json.JSONDecodeError, KeyError, IndexError) as exc:  # pragma: no cover
            raise LLMError(f"{self.service_label} returned an unexpected response shape.") from exc
        if not text:
            raise LLMError(f"{self.service_label} returned an empty response.")
        return str(text).strip()


class OpenAIProvider(OpenAICompatProvider):
    name = "openai"
    base_url = "https://api.openai.com/v1"
    api_key_env = "OPENAI_API_KEY"
    default_model = "gpt-4o-mini"
    service_label = "OpenAI"


class OpenRouterProvider(OpenAICompatProvider):
    name = "openrouter"
    base_url = "https://openrouter.ai/api/v1"
    api_key_env = "OPENROUTER_API_KEY"
    default_model = "meta-llama/llama-3.1-8b-instruct:free"
    service_label = "OpenRouter"
