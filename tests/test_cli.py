"""End-to-end CLI tests driving the Typer app with a mocked LLM and Loki client."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from loglens import cli
from loglens.exporters import LokiError
from loglens.llm import LLMError
from loglens.llm.base import LLMProvider

runner = CliRunner()

SAMPLES = Path(__file__).resolve().parent.parent / "sample_logs"
GAME_LOG = SAMPLES / "game_server.log"
API_LOG = SAMPLES / "api_server.jsonl"


class _MockProvider(LLMProvider):
    name = "mock"

    def __init__(self) -> None:
        super().__init__(model="mock-1")

    def generate(self, prompt: str, system: str | None = None) -> str:
        return (
            "SUMMARY:\nDB primary down, checkout failed.\n\n"
            "ROOT_CAUSE:\nConnection pool exhaustion.\n\n"
            "AFFECTED_COMPONENTS:\n- db\n- checkout\n\n"
            "REMEDIATION:\n1. Fail over.\n2. Raise pool size.\n"
        )


def test_version():
    result = runner.invoke(cli.app, ["--version"])
    assert result.exit_code == 0
    assert "loglens" in result.stdout


def test_analyze_semantic_and_infer():
    result = runner.invoke(
        cli.app, ["analyze", str(GAME_LOG), "--no-llm", "--semantic", "--infer-severity"]
    )
    assert result.exit_code == 0


def test_analyze_with_baseline():
    result = runner.invoke(
        cli.app, ["analyze", str(GAME_LOG), "--no-llm", "--baseline", str(API_LOG)]
    )
    assert result.exit_code == 0


def test_diff_command(tmp_path: Path):
    before = tmp_path / "before.log"
    after = tmp_path / "after.log"
    before.write_text("2026-06-14 09:03:14 ERROR [db] timeout\n", encoding="utf-8")
    after.write_text(
        "2026-06-14 09:03:14 ERROR [db] timeout\n"
        "2026-06-14 09:03:14 ERROR [db] timeout\n"
        "2026-06-14 09:03:16 CRITICAL [pay] gateway down\n",
        encoding="utf-8",
    )
    result = runner.invoke(cli.app, ["diff", str(before), str(after)])
    assert result.exit_code == 0
    assert "new" in result.stdout
    assert "worsened" in result.stdout


def test_diff_invalid_min_level(tmp_path: Path):
    f = tmp_path / "x.log"
    f.write_text("2026-06-14 09:03:14 ERROR boom\n", encoding="utf-8")
    result = runner.invoke(cli.app, ["diff", str(f), str(f), "--min-level", "NOPE"])
    assert result.exit_code == 2


def test_analyze_no_llm_text():
    result = runner.invoke(cli.app, ["analyze", str(GAME_LOG), "--no-llm"])
    assert result.exit_code == 0
    assert "Incident Report" in result.stdout
    assert "Temporal & Cascade Analysis" in result.stdout


def test_analyze_no_llm_json_with_output(tmp_path: Path):
    out = tmp_path / "report.md"
    result = runner.invoke(cli.app, ["analyze", str(API_LOG), "--no-llm", "--output", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    assert "# Incident Report" in out.read_text(encoding="utf-8")


def test_analyze_drain_no_llm():
    result = runner.invoke(cli.app, ["analyze", str(GAME_LOG), "--no-llm", "--drain"])
    assert result.exit_code == 0
    assert "clusterer=drain" in result.stdout


def test_analyze_invalid_min_level():
    result = runner.invoke(cli.app, ["analyze", str(GAME_LOG), "--min-level", "BOGUS"])
    assert result.exit_code == 2


def test_analyze_nothing_to_triage():
    # An empty log file yields no entries -> exit 1.
    empty = GAME_LOG.parent / "_does_not_exist.log"
    result = runner.invoke(cli.app, ["analyze", str(empty), "--no-llm"])
    assert result.exit_code != 0  # Typer rejects a missing path (exists=True)


def test_analyze_empty_file(tmp_path: Path):
    blank = tmp_path / "blank.log"
    blank.write_text("\n\n", encoding="utf-8")
    result = runner.invoke(cli.app, ["analyze", str(blank), "--no-llm"])
    assert result.exit_code == 1


def test_analyze_high_threshold_no_clusters(tmp_path: Path):
    only_info = tmp_path / "info.log"
    only_info.write_text("2024-01-01 00:00:00 INFO all good\n", encoding="utf-8")
    result = runner.invoke(
        cli.app, ["analyze", str(only_info), "--no-llm", "--min-level", "CRITICAL"]
    )
    assert result.exit_code == 0
    assert "nothing to triage" in result.stdout


def test_analyze_llm_path(monkeypatch):
    monkeypatch.setattr(cli, "get_provider", lambda *a, **k: _MockProvider())
    result = runner.invoke(cli.app, ["analyze", str(GAME_LOG), "--redact"])
    assert result.exit_code == 0
    assert "Connection pool exhaustion" in result.stdout


def test_analyze_llm_error(monkeypatch):
    def boom(*a, **k):
        raise LLMError("backend unreachable")

    monkeypatch.setattr(cli, "get_provider", lambda *a, **k: _MockProvider())
    monkeypatch.setattr(cli, "generate_report", boom)
    result = runner.invoke(cli.app, ["analyze", str(GAME_LOG)])
    assert result.exit_code == 3


def test_ship_success(monkeypatch):
    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def push(self, streams):
            return sum(len(s["values"]) for s in streams)

    monkeypatch.setattr(cli, "LokiClient", FakeClient)
    result = runner.invoke(cli.app, ["ship", str(GAME_LOG)])
    assert result.exit_code == 0
    assert "Shipped" in result.stdout


def test_ship_error(monkeypatch):
    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def push(self, streams):
            raise LokiError("loki down")

    monkeypatch.setattr(cli, "LokiClient", FakeClient)
    result = runner.invoke(cli.app, ["ship", str(GAME_LOG)])
    assert result.exit_code == 3


def test_ship_min_level_filter(monkeypatch, tmp_path: Path):
    log = tmp_path / "mixed.log"
    log.write_text(
        "2024-01-01 00:00:00 INFO fine\n2024-01-01 00:00:01 ERROR boom\n",
        encoding="utf-8",
    )

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def push(self, streams):
            return sum(len(s["values"]) for s in streams)

    monkeypatch.setattr(cli, "LokiClient", FakeClient)
    result = runner.invoke(cli.app, ["ship", str(log), "--min-level", "ERROR"])
    assert result.exit_code == 0


def test_ship_invalid_min_level():
    result = runner.invoke(cli.app, ["ship", str(GAME_LOG), "--min-level", "NOPE"])
    assert result.exit_code == 2
