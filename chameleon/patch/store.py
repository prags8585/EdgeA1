"""Patch store: versioned, with rollback.

Nothing is ever auto-applied. A patch only reaches 'approved' after the
replay test, the normal-traffic test, and the verifier all pass -- see
chameleon.patch.pipeline for the orchestration.

Every write is mirrored to the Redis patch store (chameleon.patch.redis_store),
and every change to the approved set is rendered into the four demo apps as
Python (chameleon.patch.integrate).
"""
from __future__ import annotations

import json
import time
import uuid

from . import integrate, redis_store


def _next_version(conn, attack_type: str) -> int:
    row = conn.execute(
        "SELECT MAX(version) AS v FROM patches WHERE attack_type = ?", (attack_type,)
    ).fetchone()
    return (row["v"] or 0) + 1


def propose(conn, rule: dict, writer_model: str) -> str:
    patch_id = str(uuid.uuid4())
    version = _next_version(conn, rule["attack_type"])
    now = time.time()
    conn.execute(
        """INSERT INTO patches (id, version, status, attack_type, rule_json, writer_model, created_at)
           VALUES (?, ?, 'proposed', ?, ?, ?, ?)""",
        (patch_id, version, rule["attack_type"], json.dumps(rule), writer_model, now),
    )
    conn.commit()
    redis_store.record_proposed(patch_id, version, rule, writer_model, now)
    return patch_id


def log_event(conn, patch_id: str, stage: str, result: str, reason: str | None = None) -> None:
    now = time.time()
    conn.execute(
        "INSERT INTO patch_events (id, patch_id, stage, result, reason, ts) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), patch_id, stage, result, reason, now),
    )
    conn.commit()
    redis_store.record_event(patch_id, stage, result, reason, now)


def set_status(conn, patch_id: str, status: str) -> None:
    before = conn.execute("SELECT status FROM patches WHERE id = ?", (patch_id,)).fetchone()
    conn.execute("UPDATE patches SET status = ? WHERE id = ?", (status, patch_id))
    conn.commit()
    redis_store.record_status(patch_id, status)
    if "approved" in (status, before and before["status"]):
        integrate.sync_active(conn)


def rollback(conn, patch_id: str) -> None:
    set_status(conn, patch_id, "rolled_back")


def active_rules(conn) -> list[dict]:
    """The rules enforced at the front door: Redis's active set when Redis is
    up, else SQLite's approved rows."""
    from_redis = redis_store.active_rules()
    if from_redis is not None:
        return from_redis
    rows = conn.execute(
        "SELECT rule_json FROM patches WHERE status = 'approved' ORDER BY created_at"
    ).fetchall()
    return [json.loads(r["rule_json"]) for r in rows]


def backfill_redis(conn) -> int:
    """Copy patches that predate Redis (or were written while it was down) into
    it, with their test trails and status. Idempotent."""
    r = redis_store.client()
    if r is None:
        return 0
    copied = 0
    for row in conn.execute("SELECT * FROM patches ORDER BY created_at").fetchall():
        if r.exists(f"{redis_store.PREFIX}patch:{row['id']}"):
            continue
        redis_store.record_proposed(row["id"], row["version"], json.loads(row["rule_json"]),
                                    row["writer_model"], row["created_at"])
        for ev in conn.execute("SELECT * FROM patch_events WHERE patch_id = ? ORDER BY ts", (row["id"],)):
            redis_store.record_event(row["id"], ev["stage"], ev["result"], ev["reason"], ev["ts"])
        if row["status"] != "proposed":
            redis_store.record_status(row["id"], row["status"])
        copied += 1
    return copied
