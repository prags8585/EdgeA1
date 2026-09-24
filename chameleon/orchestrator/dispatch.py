"""Decide where a job runs (the Nano, or the configured cloud fallback) and run it.

Default is always the Nano. Falls back to cloud only when the Nano model
for that job isn't ready, and every call -- Nano or cloud -- is logged
(chameleon.llm / llm_calls) with a placement_reason, latency, tokens, and
cost. That's what organizer answers 1 and 4 asked for (HANDOFF.md section 3).
"""
from __future__ import annotations

import json
import subprocess
import time

from .. import config, db, llm
from . import cloud, policy


def nano_is_ready(model_label: str, timeout: float = 5.0) -> bool:
    """Ask zrt directly whether this label's backend is up and Ready."""
    try:
        result = subprocess.run(
            ["zrt", "services", "--json"], capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode != 0:
            return False
        data = json.loads(result.stdout)
        return any(
            p.get("label") == model_label and p.get("state") == "Ready"
            for p in data.get("processes", [])
        )
    except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError):
        return False


def run_job(
    job: str,
    system: str,
    user: str,
    *,
    conn=None,
    session_id: str | None = None,
    nano_ready: bool | None = None,
) -> str:
    """Run one AI job ("honeypot_turn" | "write_patch" | "verify_patch"),
    preferring the Nano model configured for it in config/routing.yaml and
    falling back to cloud only if that model isn't ready. Returns the reply
    text.
    """
    pol = policy.load_policy()
    nano_model = pol["jobs"][job]["nano_model"]

    if nano_ready is None:
        nano_ready = nano_is_ready(nano_model)

    if nano_ready:
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        return llm.timed_call(
            role=job, model=nano_model, messages=messages, conn=conn,
            session_id=session_id, provider="nano", placement_reason="nano_ready",
        )

    fallback = pol["cloud_fallback"]
    owns_conn = conn is None
    conn = conn or db.get_connection()
    start = time.perf_counter()
    try:
        db.init_db(conn)
        result = cloud.chat(fallback["provider"], system, user, fallback["model"])
        latency_ms = (time.perf_counter() - start) * 1000
        cost = (
            (result["in_tokens"] / 1000) * config.CLOUD_PRICE_IN_PER_1K
            + (result["out_tokens"] / 1000) * config.CLOUD_PRICE_OUT_PER_1K
        )
        db.log_llm_call(
            conn, provider="cloud", model=fallback["model"], role=job,
            latency_ms=latency_ms, in_tokens=result["in_tokens"], out_tokens=result["out_tokens"],
            est_cost_usd=cost, ok=True, session_id=session_id, placement_reason="nano_unreachable",
        )
        return result["text"]
    except Exception as exc:
        latency_ms = (time.perf_counter() - start) * 1000
        db.log_llm_call(
            conn, provider="cloud", model=fallback["model"], role=job,
            latency_ms=latency_ms, ok=False, error=str(exc), session_id=session_id,
            placement_reason="nano_unreachable",
        )
        raise
    finally:
        if owns_conn:
            conn.close()
