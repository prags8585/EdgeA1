"""Backend API + dashboard for Chameleon Edge.

REST endpoints read straight from SQLite -- no caching, this is a 1-day
build and the dataset is small. The WebSocket pushes the summary once a
second so the dashboard updates live without client-side polling.
"""
from __future__ import annotations

import asyncio
import json

import httpx
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .. import config, db, router
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
        return {
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


@app.post("/api/scenario/run")
def run_scenario():
    conn = _conn()
    try:
        result = redteam_scenario.run(conn, CHECK_DATA_DIR)
        return {
            "wave1_detection_rate": result["wave1_detection_rate"],
            "wave2_detection_rate": result["wave2_detection_rate"],
            "patch_result": result["patch_result"],
            "event_count": len(result["events"]),
        }
    finally:
        conn.close()


# Which demo-app endpoint a field belongs to, so a request judged safe is
# forwarded exactly the way the real app would receive it.
FIELD_ROUTES = {
    "q": ("GET", "/search"),
    "name": ("GET", "/files"),
    "message": ("POST", "/chat"),
}


class TryRequest(BaseModel):
    field: str = Field(pattern="^(q|name|message)$")
    value: str = Field(min_length=1, max_length=4000)


def _forward_to_app(field: str, value: str) -> dict:
    method, path = FIELD_ROUTES[field]
    url = f"{config.DEMO_APP_URL}{path}"
    try:
        if method == "GET":
            resp = httpx.get(url, params={field: value}, timeout=10)
        else:
            resp = httpx.post(url, json={field: value}, timeout=10)
    except httpx.HTTPError as exc:
        return {"status": None, "body": f"demo app unreachable: {exc}", "canary_leaked": False}
    body = resp.text
    return {"status": resp.status_code, "body": body, "canary_leaked": "CANARY-" in body}


@app.post("/api/try")
def try_request(req: TryRequest):
    """Send one request through the real front door, the way live traffic goes."""
    try:
        result = router.handle_request({req.field: req.value})
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail=f"a model service is unreachable: {exc}") from exc
    out = {
        "decision": result["decision"],
        "reason": result["reason"],
        "nano_score": result["nano_score"],
        "rule_id": result.get("rule_id"),
        "routed_to": result["routed_to"],
    }
    if result["routed_to"] == "honeypot":
        out["honeypot_reply"] = result["honeypot_reply"]
    else:
        out["app_response"] = _forward_to_app(req.field, req.value)
    return out


@app.post("/api/demo/reset")
def reset_demo():
    """Wipe every table for a clean demo run. Trained models on disk are untouched."""
    conn = _conn()
    try:
        # Children before parents: attack_events -> sessions and patch_events -> patches
        # are foreign keys (enforced), so the other order fails once real data exists.
        for table in ("attack_events", "patch_events", "sessions", "patches", "requests", "llm_calls", "runs"):
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
