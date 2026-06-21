"""Ollama provider — the default, fully local, no-API-key backend.

Talks to a local Ollama daemon (https://ollama.com) over its HTTP API. Nothing
leaves the machine, which makes it the responsible default for log data.
"""

from __future__ import annotations

import json
import os

import requests

from ..base import LLMError, LLMProvider

DEFAULT_MODEL = "llama3.2"
DEFAULT_HOST = "http://localhost:11434"


class OllamaProvider(LLMProvider):
    """Generate completions via a local Ollama server."""

    name = "ollama"

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        host: str | None = None,
        timeout: float = 120.0,
    ) -> None:
        super().__init__(model=model, timeout=timeout)
        self.host = (host or os.environ.get("OLLAMA_HOST") or DEFAULT_HOST).rstrip("/")

    @property
    def endpoint(self) -> str:
        return f"{self.host}/api/generate"

    def generate(self, prompt: str, system: str | None = None) -> str:
        payload: dict[str, object] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        if system:
            payload["system"] = system

        try:
            response = requests.post(self.endpoint, json=payload, timeout=self.timeout)
        except requests.exceptions.ConnectionError as exc:
            raise LLMError(
                f"Could not reach Ollama at {self.host}. Is it running? "
                "Start it with `ollama serve` and `ollama pull "
                f"{self.model}`."
            ) from exc
        except requests.RequestException as exc:  # pragma: no cover - network
            raise LLMError(f"Ollama request failed: {exc}") from exc

        if response.status_code == 404:
            raise LLMError(
                f"Ollama model '{self.model}' not found. "
                f"Pull it first: `ollama pull {self.model}`."
            )
        if response.status_code >= 400:
            raise LLMError(f"Ollama returned HTTP {response.status_code}: {response.text[:200]}")

        try:
            data = response.json()
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive
            raise LLMError("Ollama returned a non-JSON response.") from exc

        text = data.get("response")
        if not text:
            raise LLMError("Ollama returned an empty response.")
        return str(text).strip()
