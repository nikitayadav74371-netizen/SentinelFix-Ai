"""Sentinel AI - FastAPI application (served by uvicorn)."""
from __future__ import annotations
import json
import os
import shutil
import threading
import time
import uuid
from typing import Dict, List

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from backend.agents.orchestrator import Orchestrator
from backend.llm_client import OllamaClient
from backend.models.schemas import JobState, ScanRequest
from backend.reports import build_zip
from backend.scanner.file_scanner import discover_files
from backend.scanner import git_handler
from backend.chatbot import router as chat_router

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKSPACE = os.path.join(BASE_DIR, "workspace", "jobs")
FRONTEND = os.path.join(BASE_DIR, "frontend")
os.makedirs(WORKSPACE, exist_ok=True)

app = FastAPI(title="Sentinel AI", version="1.0.0")

JOBS: Dict[str, JobState] = {}
EVENTS: Dict[str, List[dict]] = {}
LOCK = threading.Lock()


def _emit_factory(job_id: str):
    def emit(event: dict):
        event["ts"] = time.time()
        with LOCK:
            EVENTS[job_id].append(event)
    return emit


def _prepare_source(req: ScanRequest, job_id: str) -> tuple[str, str, dict]:
    """Validate the requested source and return (scan_root, label, extra_info).
    Raises GitValidationError with a user-friendly message on any problem."""
    info: dict = {}
    if req.source_type == "github":
        if not req.github_url:
            raise git_handler.GitValidationError("Please enter a GitHub repository URL.")
        local_ref = None
        if req.local_path and req.local_path.strip():
            local_ref = git_handler.validate_local_path(req.local_path)
        clone = git_handler.clone_repo(req.github_url, WORKSPACE, job_id)
        if not discover_files(clone.local_dir):
            raise git_handler.GitValidationError(
                "The repository was cloned but contains no supported source files "
                "(.py .js .css .php .c .cpp .html ...)."
            )
        if local_ref:
            info["parity"] = git_handler.compare_local_vs_clone(local_ref, clone.local_dir)
        return clone.local_dir, f"GitHub: {clone.owner}/{clone.repo}", info

    if not req.local_path or not req.local_path.strip():
        raise git_handler.GitValidationError("Please enter a folder or file path.")
    raw = os.path.abspath(os.path.expanduser(req.local_path.strip().strip('"')))
    if os.path.isfile(raw):
        # Single-file scan: stage a one-file directory so the pipeline is unchanged.
        stage = os.path.join(WORKSPACE, job_id, "single")
        os.makedirs(stage, exist_ok=True)
        shutil.copy2(raw, os.path.join(stage, os.path.basename(raw)))
        root = stage
        label = f"File: {raw}"
    else:
        root = git_handler.validate_local_path(raw)
        label = f"Local: {root}"
    if not discover_files(root):
        raise git_handler.GitValidationError(
            "No supported source files were found there. Supported: .py .js .ts .php .c .cpp .h .css .html"
        )
    return root, label, info


def _run_job(job: JobState, source_root: str, label: str):
    emit = _emit_factory(job.job_id)
    output_root = os.path.join(WORKSPACE, job.job_id, "patched")
    try:
        job.status = "scanning"
        orch = Orchestrator(job, emit)
        orch.run(source_root, output_root)
        from backend.reports import build_zip
        zip_path = os.path.join(WORKSPACE, job.job_id, "SentinelAI_Result.zip")
        build_zip(job, output_root, zip_path, label)
        job.output_zip = zip_path
        job.status = "done"
        emit({"type": "done", "summary": job.summary})
    except Exception as e:  # noqa
        job.status = "error"
        job.error = str(e)
        emit({"type": "error", "message": str(e)})


@app.get("/api/health")
def health(host: str = Query("http://localhost:11434")):
    client = OllamaClient(host=host)
    models = client.list_models()
    return {"ok": True, "ollama_available": bool(models) or client.is_available(), "models": models}


@app.post("/api/scan")
def start_scan(req: ScanRequest):
    job_id = uuid.uuid4().hex[:10]
    try:
        root, label, info = _prepare_source(req, job_id)
    except git_handler.GitValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    job = JobState(job_id=job_id, request=req, resolved_root=root)
    with LOCK:
        JOBS[job_id] = job
        EVENTS[job_id] = []
    _emit_factory(job_id)({"type": "source_validated", "label": label, **info})
    threading.Thread(target=_run_job, args=(job, root, label), daemon=True).start()
    return {"job_id": job_id, "label": label, "parity": info.get("parity")}


@app.get("/api/scan/{job_id}/events")
def stream_events(job_id: str, start: int = 0):
    if job_id not in JOBS:
        raise HTTPException(404, "Unknown job")

    def gen():
        idx = start
        while True:
            with LOCK:
                batch = EVENTS[job_id][idx:]
            for ev in batch:
                yield f"id: {idx}\ndata: {json.dumps(ev, default=str)}\n\n"
                idx += 1
                if ev.get("type") in ("done", "error"):
                    return
            time.sleep(0.15)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/scan/{job_id}")
def get_result(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Unknown job")
    return JSONResponse({
        "job_id": job_id, "status": job.status, "error": job.error, "summary": job.summary,
        "files_total": job.files_total,
        "findings": [lc.model_dump(mode="json") for lc in job.findings],
    })


@app.get("/api/scan/{job_id}/download")
def download(job_id: str):
    job = JOBS.get(job_id)
    if not job or not job.output_zip or not os.path.exists(job.output_zip):
        raise HTTPException(404, "Result not ready")
    return FileResponse(job.output_zip, media_type="application/zip", filename=f"SentinelAI_Result_{job_id}.zip")


app.mount("/assets", StaticFiles(directory=FRONTEND), name="assets")





app.include_router(chat_router)
@app.get("/chatbot")
def chatbot_page():
    return FileResponse(os.path.join(FRONTEND, "chatbot.html"))

@app.get("/")
def index():
    return FileResponse(os.path.join(FRONTEND, "index.html"))
