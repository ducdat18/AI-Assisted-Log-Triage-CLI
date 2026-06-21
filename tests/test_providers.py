"""Tests for the hosted LLM providers (OpenAI/OpenRouter/Anthropic), mocked."""

from __future__ import annotations

import pytest

from loglens.llm import LLMError, available_providers, get_provider
from loglens.llm.providers import anthropic, openai_compat


def test_new_providers_registered():
    names = available_providers()
    for name in ("openai", "openrouter", "anthropic"):
        assert name in names


def test_openai_missing_key_raises(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider = get_provider("openai")
    with pytest.raises(LLMError, match="API key not set"):
        provider.generate("hi")


def test_openai_generate_mocked(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    class FakeResp:
        status_code = 200

        @staticmethod
        def json():
            return {"choices": [{"message": {"content": "an answer"}}]}

    monkeypatch.setattr(openai_compat.requests, "post", lambda *a, **k: FakeResp())
    provider = get_provider("openai")
    assert provider.generate("prompt", system="sys") == "an answer"


def test_openrouter_uses_its_base_url_and_key(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-test")
    captured = {}

    class FakeResp:
        status_code = 200

        @staticmethod
        def json():
            return {"choices": [{"message": {"content": "ok"}}]}

    def fake_post(url, headers=None, json=None, timeout=None):
        captured["url"] = url
        captured["auth"] = headers["Authorization"]
        return FakeResp()

    monkeypatch.setattr(openai_compat.requests, "post", fake_post)
    get_provider("openrouter").generate("p")
    assert "openrouter.ai" in captured["url"]
    assert captured["auth"] == "Bearer or-test"


def test_anthropic_generate_mocked(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")

    class FakeResp:
        status_code = 200

        @staticmethod
        def json():
            return {"content": [{"text": "claude says hi"}]}

    monkeypatch.setattr(anthropic.requests, "post", lambda *a, **k: FakeResp())
    assert get_provider("anthropic").generate("p") == "claude says hi"


def test_anthropic_http_error(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")

    class FakeResp:
        status_code = 429
        text = "rate limited"

    monkeypatch.setattr(anthropic.requests, "post", lambda *a, **k: FakeResp())
    with pytest.raises(LLMError, match="HTTP 429"):
        get_provider("anthropic").generate("p")
