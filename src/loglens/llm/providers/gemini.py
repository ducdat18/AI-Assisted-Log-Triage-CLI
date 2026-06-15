"""Gemini provider — Google's free-tier hosted backend.

Reads the API key from ``GEMINI_API_KEY``. Uses the public Generative Language
REST endpoint so no extra SDK dependency is required. Because this sends data
off-machine, pair it with ``--redact`` when logs may contain sensitive data.
"""

from __future__ import annotations

import json
import os

import requests

from ..base import LLMError, LLMProvider

DEFAULT_MODEL = "gemini-1.5-flash"
API_ROOT = "https://generativelanguage.googleapis.com/v1beta/models"


class GeminiProvider(LLMProvider):
    """Generate completions via Google's Gemini free-tier API."""

    name = "gemini"

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        api_key: str | None = None,
        timeout: float = 120.0,
    ) -> None:
        super().__init__(model=model, timeout=timeout)
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")

    @property
    def endpoint(self) -> str:
        return f"{API_ROOT}/{self.model}:generateContent"

    def generate(self, prompt: str, system: str | None = None) -> str:
        if not self.api_key:
            raise LLMError(
                "GEMINI_API_KEY is not set. Get a free key at "
                "https://aistudio.google.com/apikey and export it, or use the "
                "default local provider with `--provider ollama`."
            )

        payload: dict[str, object] = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        }
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}

        try:
            response = requests.post(
                self.endpoint,
                params={"key": self.api_key},
                json=payload,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:  # pragma: no cover - network
            raise LLMError(f"Gemini request failed: {exc}") from exc

        if response.status_code == 429:
            raise LLMError("Gemini rate limit hit (free tier). Try again shortly.")
        if response.status_code >= 400:
            raise LLMError(
                f"Gemini returned HTTP {response.status_code}: {response.text[:200]}"
            )

        try:
            data = response.json()
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive
            raise LLMError("Gemini returned a non-JSON response.") from exc

        return self._extract_text(data)

    @staticmethod
    def _extract_text(data: dict[str, object]) -> str:
        candidates = data.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise LLMError(
                "Gemini returned no candidates "
                "(content may have been blocked by safety filters)."
            )
        content = candidates[0].get("content", {}) if isinstance(candidates[0], dict) else {}
        parts = content.get("parts", []) if isinstance(content, dict) else []
        texts = [p.get("text", "") for p in parts if isinstance(p, dict)]
        joined = "".join(texts).strip()
        if not joined:
            raise LLMError("Gemini returned an empty response.")
        return joined
