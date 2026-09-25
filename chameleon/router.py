"""The front door: decide safe vs malicious for one request, log it, route it.

First contact with an attack: the honeypot on the Nano answers as if it worked
(fake data, unique honeytokens) and a patch for that attack starts in the
background. After that: using a stolen honeytoken, or repeating an attack an
approved patch covers, is blocked outright. Safe requests go to the demo app.
"""
from __future__ import annotations

import hashlib
import time
import uuid

from . import autopatch, db, fusion
from .honeypot import deception
from .honeypot import session as honeypot_session


def _hash_inputs(field_inputs: dict[str, str]) -> str:
    joined = "\x1f".join(f"{k}={v}" for k, v in sorted(field_inputs.items()))
    return hashlib.sha256(joined.encode()).hexdigest()


def handle_request(field_inputs: dict[str, str], conn=None, auto_patch: bool = True) -> dict:
    """field_inputs: e.g. {"q": "..."} or {"username": "...", "password": "..."}.

    Three outcomes for an attack:
      - it contains a honeytoken the honeypot handed out earlier -> blocked, and
        traced back to the session that stole it;
      - it matches a patch rule already approved for that attack -> blocked;
      - otherwise, if the check model flags it -> the honeypot answers as if the
        attack worked, and (auto_patch) a patch job starts for this exact payload.
    Safe requests go to the app.
    """
    owns_conn = conn is None
    conn = conn or db.get_connection()
    try:
        db.init_db(conn)
        stolen = deception.find_stolen(conn, field_inputs)
        result = fusion.decide(field_inputs, conn=conn)
        if stolen:
            result = {**result, "decision": "malicious", "reason": "stolen_honeytoken"}
        request_id = str(uuid.uuid4())
        conn.execute(
            """INSERT INTO requests (id, ts, inputs_hash, jev_score, nano_score, decision, latency_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (request_id, time.time(), _hash_inputs(field_inputs),
             result["jev_score"], result["nano_score"], result["decision"], 0.0),
        )
        conn.commit()

        honeypot_reply = session_id = patch_job_id = blocked = None
        if stolen:
            routed_to = "blocked"
            blocked = {"why": "stolen_honeytoken", "kind": stolen["kind"],
                       "leaked_to_session": stolen["session_id"], "leaked_at": stolen["ts"]}
        elif result["reason"] == "rule_match":
            routed_to = "blocked"
            blocked = {"why": "rule_match", "rule_id": result["rule_id"]}
        elif result["decision"] == "malicious":
            routed_to = "honeypot"
            session_id = honeypot_session.start_session(session_type="web", conn=conn)
            payload = " | ".join(f"{k}={v}" for k, v in field_inputs.items())
            honeypot_reply = honeypot_session.respond(
                session_id, field=",".join(field_inputs), payload=payload, conn=conn,
            )
            if auto_patch:
                field = result.get("worst_field") or next(iter(field_inputs))
                patch_job_id = autopatch.submit(
                    conn, field, field_inputs[field], deception.attack_type(field, field_inputs[field]))
        else:
            routed_to = "app"
    finally:
        if owns_conn:
            conn.close()

    return {
        **result,
        "request_id": request_id,
        "routed_to": routed_to,
        "session_id": session_id,
        "honeypot_reply": honeypot_reply,
        "blocked": blocked,
        "patch_job_id": patch_job_id,
    }
