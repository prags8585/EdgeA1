"""Patch store: versioned, with rollback.

Nothing is ever auto-applied. A patch only reaches 'approved' after the
replay test, the normal-traffic test, and the verifier all pass -- see
chameleon.patch.pipeline for the orchestration.
"""
from __future__ import annotations

import json
import time
import uuid


def _next_version(conn, attack_type: str) -> int:
    row = conn.execute(
        "SELECT MAX(version) AS v FROM patches WHERE attack_type = ?", (attack_type,)
    ).fetchone()
    return (row["v"] or 0) + 1


def propose(conn, rule: dict, writer_model: str) -> str:
    patch_id = str(uuid.uuid4())
    version = _next_version(conn, rule["attack_type"])
    conn.execute(
        """INSERT INTO patches (id, version, status, attack_type, rule_json, writer_model, created_at)
           VALUES (?, ?, 'proposed', ?, ?, ?, ?)""",
        (patch_id, version, rule["attack_type"], json.dumps(rule), writer_model, time.time()),
    )
    conn.commit()
    return patch_id


def log_event(conn, patch_id: str, stage: str, result: str, reason: str | None = None) -> None:
    conn.execute(
        "INSERT INTO patch_events (id, patch_id, stage, result, reason, ts) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), patch_id, stage, result, reason, time.time()),
    )
    conn.commit()


def set_status(conn, patch_id: str, status: str) -> None:
    conn.execute("UPDATE patches SET status = ? WHERE id = ?", (status, patch_id))
    conn.commit()


def rollback(conn, patch_id: str) -> None:
    set_status(conn, patch_id, "rolled_back")


def active_rules(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT rule_json FROM patches WHERE status = 'approved' ORDER BY created_at"
    ).fetchall()
    return [json.loads(r["rule_json"]) for r in rows]
