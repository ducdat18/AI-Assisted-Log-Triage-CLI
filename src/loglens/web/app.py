"""FastAPI dashboard for loglens — interactive triage + realtime live-tail.

Exposes the same deterministic pipeline the CLI uses (parse → cluster →
analyze_incident → report) over HTTP, plus a Server-Sent-Events stream that tails
a growing log file. The dashboard renders what Grafana cannot: the incident
onset, the cause→effect cascade graph, and per-finding confidence.

This module is imported only by ``loglens serve`` and the web tests; the core CLI
never depends on FastAPI.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Iterator
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from ..clustering import cluster_and_rank
from ..incident import (
    analyze_incident,
    deterministic_report,
    evidence_block,
    findings_to_dict,
)
from ..live import tail_entries
from ..llm import LLMError, get_provider
from ..parser import Severity, parse_file
from ..semantic import merge_similar
from .simulator import Simulator

_CHAT_SYSTEM = (
    "You are loglens, an SRE incident assistant. Answer the user's question about "
    "the log/incident concisely. When COMPUTED EVIDENCE is provided, treat its "
    "onset, trigger, and cascade as ground truth and base your answer on it rather "
    "than guessing."
)

_HERE = Path(__file__).resolve().parent
_MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MB cap on uploaded logs


def _resolve_in(logs_dir: Path, rel: str) -> Path:
    """Resolve ``rel`` under ``logs_dir``, rejecting path traversal."""

    candidate = (logs_dir / rel).resolve()
    if candidate != logs_dir.resolve() and logs_dir.resolve() not in candidate.parents:
        raise HTTPException(status_code=403, detail="Path is outside the logs directory.")
    if not candidate.is_file():
        raise HTTPException(status_code=404, detail="Log file not found.")
    return candidate


def _evidence_for(path: str) -> str:
    """Deterministic evidence block for a log, used to ground the chatbot."""

    entries = parse_file(path)
    clusters = cluster_and_rank(entries, min_level=Severity.WARNING)
    if not clusters:
        return "No WARNING+ entries found in the selected log."
    findings = analyze_incident(entries, clusters)
    top = "\n".join(f"- [{c.level.name if c.level else '?'}] {c.template}" for c in clusters[:8])
    return f"{evidence_block(findings)}\n\nTop clusters:\n{top}"


def _analyze_path(path: str, *, min_level: str, drain: bool, semantic: bool) -> dict[str, object]:
    """Run the deterministic pipeline over a file and return a JSON-able result."""

    threshold = Severity.from_text(min_level) or Severity.WARNING
    entries = parse_file(path)
    if not entries:
        raise HTTPException(status_code=422, detail="No log lines found.")
    method = "drain" if drain else "regex"
    if semantic:
        clusters = merge_similar(cluster_and_rank(entries, min_level=threshold, method=method))
    else:
        clusters = cluster_and_rank(entries, min_level=threshold, method=method)
    if not clusters:
        return {"clusters": [], "findings": None, "report": None, "parsed": len(entries)}
    findings = analyze_incident(entries, clusters)
    report = deterministic_report(findings, clusters, source=Path(path).name)
    return {
        "parsed": len(entries),
        "clusters": [
            {
                "level": c.level.name if c.level else "UNKNOWN",
                "count": c.count,
                "component": c.component,
                "template": c.template,
            }
            for c in clusters
        ],
        "findings": findings_to_dict(findings),
        "report": report.to_dict(Path(path).name),
    }


def create_app(logs_dir: str | Path = ".", default_provider: str | None = None) -> FastAPI:
    """Build the dashboard app rooted at ``logs_dir`` (the only browsable tree)."""

    root = Path(logs_dir).resolve()
    app = FastAPI(title="loglens dashboard", docs_url="/api/docs")
    templates = Jinja2Templates(directory=str(_HERE / "templates"))
    app.mount("/static", StaticFiles(directory=str(_HERE / "static")), name="static")

    _SIM_NAME = "_sim.log"
    simulator = Simulator(root / _SIM_NAME)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        files = sorted(
            str(p.relative_to(root))
            for p in root.rglob("*")
            if p.is_file() and p.suffix in (".log", ".txt", ".jsonl", ".gz")
        )
        return templates.TemplateResponse(
            request, "index.html", {"files": files, "logs_dir": str(root)}
        )

    @app.post("/api/analyze")
    async def api_analyze(
        path: str | None = Form(default=None),
        upload: UploadFile | None = None,
        min_level: str = Form(default="WARNING"),
        drain: bool = Form(default=False),
        semantic: bool = Form(default=False),
    ) -> dict[str, object]:
        if upload is not None:
            data = await upload.read()
            if len(data) > _MAX_UPLOAD_BYTES:
                raise HTTPException(status_code=413, detail="Uploaded log too large.")
            with tempfile.NamedTemporaryFile(
                "wb", suffix="-" + (upload.filename or "upload.log"), delete=False
            ) as tmp:
                tmp.write(data)
                target = tmp.name
        elif path:
            target = str(_resolve_in(root, path))
        else:
            raise HTTPException(status_code=400, detail="Provide a 'path' or an upload.")
        return _analyze_path(target, min_level=min_level, drain=drain, semantic=semantic)

    @app.get("/api/stream")
    def api_stream(
        path: str = Query(...),
        min_level: str = Query(default="ERROR"),
    ) -> StreamingResponse:
        target = _resolve_in(root, path)
        threshold = Severity.from_text(min_level) or Severity.ERROR

        def events() -> Iterator[str]:
            yield f"data: {json.dumps({'type': 'connected', 'path': path})}\n\n"
            for surfaced in tail_entries(str(target), threshold=threshold):
                payload = {
                    "type": "line",
                    "time": surfaced.timestamp.strftime("%H:%M:%S") if surfaced.timestamp else "",
                    "level": surfaced.level.name,
                    "message": surfaced.message,
                    "is_new": surfaced.is_new,
                }
                yield f"data: {json.dumps(payload)}\n\n"

        return StreamingResponse(events(), media_type="text/event-stream")

    @app.post("/api/simulate")
    def api_simulate(speed: float = Form(default=1.0)) -> dict[str, object]:
        """Start writing a synthetic incident to ``_sim.log`` for a live demo."""

        simulator.start(speed=max(0.25, min(speed, 20.0)))
        return {"path": _SIM_NAME, "running": simulator.running}

    @app.post("/api/simulate/stop")
    def api_simulate_stop() -> dict[str, object]:
        simulator.stop()
        return {"running": False}

    @app.post("/api/chat")
    def api_chat(
        message: str = Form(...),
        path: str | None = Form(default=None),
    ) -> dict[str, str]:
        """Answer a question about the incident, grounded on computed evidence."""

        context = ""
        if path:
            context = _evidence_for(str(_resolve_in(root, path)))
        prompt = (
            f"--- COMPUTED EVIDENCE ---\n{context}\n\n" if context else ""
        ) + f"Question: {message}"
        try:
            backend = get_provider(default_provider)
            answer = backend.generate(prompt, system=_CHAT_SYSTEM)
        except LLMError as exc:
            return {"answer": f"(LLM unavailable: {exc})"}
        return {"answer": answer}

    return app
