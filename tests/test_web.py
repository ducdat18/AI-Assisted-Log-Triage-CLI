"""Tests for the FastAPI dashboard (deterministic, offline)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from loglens.web import create_app

SAMPLES = Path(__file__).resolve().parent.parent / "sample_logs"


def _client() -> TestClient:
    return TestClient(create_app(logs_dir=SAMPLES))


def test_healthz():
    assert _client().get("/healthz").json() == {"status": "ok"}


def test_index_lists_files():
    res = _client().get("/")
    assert res.status_code == 200
    assert "game_server.log" in res.text
    assert "incident dashboard" in res.text


def test_analyze_by_path_returns_findings():
    res = _client().post(
        "/api/analyze",
        data={"path": "game_server.log", "min_level": "WARNING"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["findings"]["onset"] is not None
    assert data["report"]["summary"]
    assert data["clusters"]
    # Cascade links carry confidence for the graph.
    if data["findings"]["cascade"]:
        assert "confidence" in data["findings"]["cascade"][0]


def test_analyze_upload():
    files = {"upload": ("u.log", b"2026-06-14 09:03:15 ERROR [db] boom\n", "text/plain")}
    res = _client().post("/api/analyze", files=files, data={"min_level": "WARNING"})
    assert res.status_code == 200
    assert res.json()["parsed"] == 1


def test_analyze_path_traversal_blocked():
    res = _client().post("/api/analyze", data={"path": "../pyproject.toml"})
    assert res.status_code == 403


def test_analyze_missing_input():
    res = _client().post("/api/analyze", data={})
    assert res.status_code == 400


def test_stream_rejects_outside_path():
    res = _client().get("/api/stream", params={"path": "../pyproject.toml"})
    assert res.status_code in (403, 404)


def test_simulate_start_and_stop(tmp_path):
    client = TestClient(create_app(logs_dir=tmp_path))
    res = client.post("/api/simulate", data={"speed": "20"})
    assert res.status_code == 200
    assert res.json()["path"] == "_sim.log"
    stop = client.post("/api/simulate/stop")
    assert stop.json() == {"running": False}
    assert (tmp_path / "_sim.log").exists()


def test_chat_grounded_with_mocked_provider(monkeypatch):
    from loglens.web import app as webapp

    class FakeProvider:
        def generate(self, prompt, system=None):
            assert "COMPUTED EVIDENCE" in prompt  # grounded on the selected log
            return "The database primary failed first."

    monkeypatch.setattr(webapp, "get_provider", lambda *a, **k: FakeProvider())
    res = _client().post("/api/chat", data={"message": "what happened?", "path": "game_server.log"})
    assert res.status_code == 200
    assert "database primary" in res.json()["answer"]


def test_chat_without_path(monkeypatch):
    from loglens.web import app as webapp

    class FakeProvider:
        def generate(self, prompt, system=None):
            return "ask me about a specific log"

    monkeypatch.setattr(webapp, "get_provider", lambda *a, **k: FakeProvider())
    res = _client().post("/api/chat", data={"message": "hi"})
    assert res.status_code == 200
    assert res.json()["answer"]


def test_chat_llm_unavailable(monkeypatch):
    from loglens.llm import LLMError
    from loglens.web import app as webapp

    def boom(*a, **k):
        raise LLMError("no backend")

    monkeypatch.setattr(webapp, "get_provider", boom)
    res = _client().post("/api/chat", data={"message": "hi"})
    assert res.status_code == 200
    assert "LLM unavailable" in res.json()["answer"]
