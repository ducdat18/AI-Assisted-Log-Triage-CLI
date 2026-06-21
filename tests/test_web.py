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
