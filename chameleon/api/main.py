"""Backend API + dashboard for Chameleon Edge.

REST endpoints read straight from SQLite -- no caching, this is a 1-day
build and the dataset is small. The WebSocket pushes the summary once a
second so the dashboard updates live without client-side polling.
"""
from __future__ import annotations

import asyncio
import json
import threading
import time

import httpx
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .. import autopatch, cloud_mirror, config, db, router
from ..honeypot import deception
from ..redteam import scenario as redteam_scenario

app = FastAPI(title="Chameleon Edge dashboard")

DASHBOARD_HTML = config.ROOT / "dashboard" / "index.html"
CHECK_DATA_DIR = config.ROOT / "data" / "check"


def _conn():
    conn = db.get_connection()
    db.init_db(conn)
    return conn


@app.get("/")
def dashboard():
    return FileResponse(DASHBOARD_HTML)


@app.get("/api/summary")
def summary():
    conn = _conn()
    try:
        total = conn.execute("SELECT COUNT(*) AS n FROM requests").fetchone()["n"]
        malicious = conn.execute(
            "SELECT COUNT(*) AS n FROM requests WHERE decision = 'malicious'"
        ).fetchone()["n"]
        sessions_open = conn.execute("SELECT COUNT(*) AS n FROM sessions WHERE status = 'open'").fetchone()["n"]
        sessions_total = conn.execute("SELECT COUNT(*) AS n FROM sessions").fetchone()["n"]
        patches_by_status = {
            r["status"]: r["n"]
            for r in conn.execute("SELECT status, COUNT(*) AS n FROM patches GROUP BY status")
        }
        calls_by_provider = {
            r["provider"]: {"n": r["n"], "cost_usd": r["cost"]}
            for r in conn.execute(
                "SELECT provider, COUNT(*) AS n, COALESCE(SUM(est_cost_usd), 0) AS cost "
                "FROM llm_calls GROUP BY provider"
            )
        }
        aws_comparison_cost = conn.execute(
            "SELECT COALESCE(SUM(aws_cost_usd), 0) AS c FROM comparisons").fetchone()["c"]
        return {
            "aws_comparison_cost_usd": aws_comparison_cost,
            "total_requests": total,
            "malicious_requests": malicious,
            "sessions_open": sessions_open,
            "sessions_total": sessions_total,
            "patches_by_status": patches_by_status,
            "calls_by_provider": calls_by_provider,
        }
    finally:
        conn.close()


@app.get("/api/requests")
def recent_requests(limit: int = 50):
    conn = _conn()
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM requests ORDER BY ts DESC LIMIT ?", (limit,))]
    finally:
        conn.close()


@app.get("/api/sessions")
def recent_sessions(limit: int = 20):
    conn = _conn()
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM sessions ORDER BY ts_start DESC LIMIT ?", (limit,))]
    finally:
        conn.close()


@app.get("/api/sessions/{session_id}/events")
def session_events(session_id: str):
    conn = _conn()
    try:
        rows = conn.execute(
            "SELECT * FROM attack_events WHERE session_id = ? ORDER BY ts", (session_id,)
        )
        return [dict(r) for r in rows]
    finally:
        conn.close()


@app.get("/api/patches")
def patches(limit: int = 50):
    conn = _conn()
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM patches ORDER BY created_at DESC LIMIT ?", (limit,))]
    finally:
        conn.close()


@app.get("/api/patches/{patch_id}/events")
def patch_events(patch_id: str):
    conn = _conn()
    try:
        rows = conn.execute("SELECT * FROM patch_events WHERE patch_id = ? ORDER BY ts", (patch_id,))
        return [dict(r) for r in rows]
    finally:
        conn.close()


@app.get("/api/llm_calls")
def llm_calls(limit: int = 50):
    conn = _conn()
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM llm_calls ORDER BY ts DESC LIMIT ?", (limit,))]
    finally:
        conn.close()


# The attack wave takes ~2-3 minutes. Holding one HTTP request open that long
# broke in the browser (observed: NetworkError mid-wave while the server kept
# working), and demos reach the Nano through SSH/VS Code tunnels that drop long
# requests. So it runs as a background job and the dashboard polls its status.
_wave_lock = threading.Lock()
_wave = {"state": "idle", "phase": None, "started_at": None, "finished_at": None, "result": None, "error": None}


def _run_wave() -> None:
    def progress(phase: str) -> None:
        with _wave_lock:
            _wave["phase"] = phase

    conn = _conn()  # sqlite connections belong to the thread that made them
    try:
        result = redteam_scenario.run(conn, CHECK_DATA_DIR, on_progress=progress)
        summary = {
            "wave1_detection_rate": result["wave1_detection_rate"],
            "wave2_detection_rate": result["wave2_detection_rate"],
            "patch_result": result["patch_result"],
            "event_count": len(result["events"]),
        }
        with _wave_lock:
            _wave.update(state="done", result=summary, finished_at=time.time())
    except Exception as exc:  # noqa: BLE001 - surfaced to the dashboard, not swallowed
        with _wave_lock:
            _wave.update(state="error", error=f"{type(exc).__name__}: {exc}", finished_at=time.time())
    finally:
        conn.close()


@app.post("/api/scenario/start")
def start_scenario():
    with _wave_lock:
        if _wave["state"] == "running":
            raise HTTPException(status_code=409, detail="an attack wave is already running")
        _wave.update(state="running", phase="starting", started_at=time.time(),
                     finished_at=None, result=None, error=None)
    threading.Thread(target=_run_wave, daemon=True, name="attack-wave").start()
    return scenario_status()


@app.get("/api/scenario/status")
def scenario_status():
    with _wave_lock:
        status = dict(_wave)
    end = status["finished_at"] or time.time()
    status["elapsed_s"] = round(end - status["started_at"], 1) if status["started_at"] else None
    return status


# Each demo-app screen, with the method, path, and fields it takes -- so a request
# judged safe is forwarded exactly the way the real app would receive it.
TARGETS = {
    "login": ("POST", "/login", ("username", "password")),
    "search": ("GET", "/search", ("q",)),
    "files": ("GET", "/files", ("name",)),
    "chat": ("POST", "/chat", ("message",)),
}


class TryRequest(BaseModel):
    target: str = Field(pattern="^(login|search|files|chat)$")
    inputs: dict[str, str]


def _forward_to_app(target: str, inputs: dict[str, str]) -> dict:
    method, path, _ = TARGETS[target]
    url = f"{config.DEMO_APP_URL}{path}"
    try:
        if method == "GET":
            resp = httpx.get(url, params=inputs, timeout=10)
        else:
            resp = httpx.post(url, json=inputs, timeout=10)
    except httpx.HTTPError as exc:
        return {"status": None, "body": f"demo app unreachable: {exc}", "canary_leaked": False}
    body = resp.text
    return {"status": resp.status_code, "body": body, "canary_leaked": "CANARY-" in body}


@app.post("/api/try")
def try_request(req: TryRequest):
    """Send one request through the real front door, the way live traffic goes."""
    fields = TARGETS[req.target][2]
    if set(req.inputs) - set(fields):
        raise HTTPException(status_code=422, detail=f"{req.target} takes only {list(fields)}")
    inputs = {f: req.inputs.get(f, "")[:4000] for f in fields}
    if not any(v.strip() for v in inputs.values()):
        raise HTTPException(status_code=422, detail="empty request")
    try:
        result = router.handle_request(inputs)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail=f"a model service is unreachable: {exc}") from exc
    out = {
        "target": req.target,
        "decision": result["decision"],
        "reason": result["reason"],
        "nano_score": result["nano_score"],
        "rule_id": result.get("rule_id"),
        "routed_to": result["routed_to"],
        "session_id": result.get("session_id"),
        "blocked": result.get("blocked"),
        "patch_job_id": result.get("patch_job_id"),
    }
    if result["routed_to"] == "honeypot":
        out["honeypot_reply"] = result["honeypot_reply"]
    elif result["routed_to"] == "app":
        out["app_response"] = _forward_to_app(req.target, inputs)
    return out


@app.get("/api/patch-jobs")
def patch_jobs(limit: int = 30):
    conn = _conn()
    try:
        return autopatch.recent(conn, limit)
    finally:
        conn.close()


@app.get("/api/honeytokens/latest")
def latest_honeytoken():
    """Demo helper: the admin credentials the honeypot most recently leaked --
    exactly what an attacker would copy out of its reply."""
    conn = _conn()
    try:
        creds = deception.latest(conn)
    finally:
        conn.close()
    if creds is None:
        raise HTTPException(status_code=404, detail="nothing leaked yet -- attack the honeypot first")
    return creds


class CompareMode(BaseModel):
    enabled: bool


@app.get("/api/compare")
def compare():
    """Nano vs AWS Bedrock, same model, measured on the requests run from Home."""
    conn = _conn()
    try:
        data = cloud_mirror.summary(conn)
    finally:
        conn.close()
    data["state"] = {
        "enabled": cloud_mirror.enabled(),
        "configured": cloud_mirror.configured(),
        "model": config.BEDROCK_MODEL_ID,
        "region": config.AWS_REGION,
        "enterprise_discount": config.ENTERPRISE_DISCOUNT,
    }
    return data


@app.post("/api/compare/mode")
def compare_mode(req: CompareMode):
    if req.enabled and not cloud_mirror.configured():
        raise HTTPException(status_code=400, detail="AWS credentials are not configured in .env")
    cloud_mirror.set_enabled(req.enabled)
    return {"enabled": cloud_mirror.enabled()}


@app.post("/api/demo/reset")
def reset_demo():
    """Wipe every table for a clean demo run. Trained models on disk are untouched."""
    with _wave_lock:
        if _wave["state"] == "running":
            raise HTTPException(status_code=409, detail="wait for the attack wave to finish before resetting")
    conn = _conn()
    try:
        # Children before parents: attack_events -> sessions and patch_events -> patches
        # are foreign keys (enforced), so the other order fails once real data exists.
        for table in ("attack_events", "patch_events", "sessions", "patches", "requests", "llm_calls",
                      "comparisons", "honeytokens", "patch_jobs", "runs"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.websocket("/ws")
async def ws_summary(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            await websocket.send_text(json.dumps(summary()))
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        pass
