"""Combine the Nano check model, Jev (when available), and approved patch
rules into one decision.

Malicious if any signal fires: the Nano model, Jev, or a rule the patch
pipeline has already approved for a past attack (this is how "the system
learns" closes the loop -- see HANDOFF.md section 5.2's amended diagram,
"Rules added to check layer"). If Jev is unavailable, fall back to the
Nano model and rules alone. All scores are returned so the caller can log
them -- the disagreement cases are the interesting evidence.
"""
from __future__ import annotations

import httpx

from . import config, db
from .jev import client as jev_client
from .patch import rules as rules_engine
from .patch import store as patch_store

JEV_THRESHOLD = 0.5


def check_nano(inputs: list[str]) -> dict:
    resp = httpx.post(f"{config.CHECK_MODEL_URL}/check", json={"inputs": inputs}, timeout=5.0)
    resp.raise_for_status()
    return resp.json()


def decide(field_inputs: dict[str, str], conn=None) -> dict:
    inputs = list(field_inputs.values())
    nano = check_nano(inputs)

    jev_score = None
    jev_available = True
    try:
        jev = jev_client.check(inputs)
        jev_score = jev["score"]
    except jev_client.JevUnavailable:
        jev_available = False

    owns_conn = conn is None
    conn = conn or db.get_connection()
    try:
        db.init_db(conn)
        rule_hit = rules_engine.blocked_by(patch_store.active_rules(conn), field_inputs)
    finally:
        if owns_conn:
            conn.close()

    malicious = nano["malicious"] or rule_hit is not None
    if jev_available:
        malicious = malicious or jev_score >= JEV_THRESHOLD

    if rule_hit is not None:
        reason = "rule_match"
    elif jev_available:
        reason = "nano_or_jev"
    else:
        reason = "nano_only_jev_unavailable"

    return {
        "decision": "malicious" if malicious else "safe",
        "nano_score": nano["score"],
        "jev_score": jev_score,
        "reason": reason,
        "rule_id": rule_hit["id"] if rule_hit else None,
    }
