"""The front door: decide safe vs malicious for one request, log it, route it.

Safe requests go to the demo app. Malicious requests are rerouted to a
honeypot session on the Nano, which keeps the attacker engaged instead of
just returning an error.
"""
from __future__ import annotations

import hashlib
import time
import uuid

from . import db, fusion
from .honeypot import session as honeypot_session


def _hash_inputs(field_inputs: dict[str, str]) -> str:
    joined = "\x1f".join(f"{k}={v}" for k, v in sorted(field_inputs.items()))
    return hashlib.sha256(joined.encode()).hexdigest()


def handle_request(field_inputs: dict[str, str], conn=None) -> dict:
    """field_inputs: e.g. {"q": "..."} or {"username": "...", "password": "..."}."""
    result = fusion.decide(list(field_inputs.values()))

    owns_conn = conn is None
    conn = conn or db.get_connection()
    try:
        db.init_db(conn)
        request_id = str(uuid.uuid4())
        conn.execute(
            """INSERT INTO requests (id, ts, inputs_hash, jev_score, nano_score, decision, latency_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (request_id, time.time(), _hash_inputs(field_inputs),
             result["jev_score"], result["nano_score"], result["decision"], 0.0),
        )
        conn.commit()

        honeypot_reply = None
        session_id = None
        if result["decision"] == "malicious":
            session_id = honeypot_session.start_session(session_type="web", conn=conn)
            payload = " | ".join(f"{k}={v}" for k, v in field_inputs.items())
            honeypot_reply = honeypot_session.respond(
                session_id, field=",".join(field_inputs), payload=payload, conn=conn,
            )
    finally:
        if owns_conn:
            conn.close()

    routed_to = "app" if result["decision"] == "safe" else "honeypot"
    return {
        **result,
        "request_id": request_id,
        "routed_to": routed_to,
        "session_id": session_id,
        "honeypot_reply": honeypot_reply,
    }
