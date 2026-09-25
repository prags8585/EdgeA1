"""Combine Jev, the Nano check model, and approved patch rules into one decision.

Jev (TypeSafe's cloud decision API) is asked first, on every request. The Nano
check model and the approved patch rules are checked as well, and the request
is malicious if any of them flags it: Jev can be steered by adversarial text,
so it is never the only line. If Jev is unavailable or slower than its budget,
the Nano decides alone. Every score is returned so the caller can log it -- the
disagreements are the interesting evidence.
"""
from __future__ import annotations

import httpx

from . import config, db
from .jev import client as jev_client
from .patch import rules as rules_engine
from .patch import store as patch_store


def check_nano(inputs: list[str]) -> dict:
    resp = httpx.post(f"{config.CHECK_MODEL_URL}/check", json={"inputs": inputs}, timeout=5.0)
    resp.raise_for_status()
    return resp.json()


def decide(field_inputs: dict[str, str], conn=None) -> dict:
    jev = jev_error = None
    try:
        jev = jev_client.check(field_inputs)
    except jev_client.JevUnavailable as exc:
        jev_error = str(exc) or "unavailable"

    nano = check_nano(list(field_inputs.values()))

    owns_conn = conn is None
    conn = conn or db.get_connection()
    try:
        db.init_db(conn)
        rule_hit = rules_engine.blocked_by(patch_store.active_rules(conn), field_inputs)
    finally:
        if owns_conn:
            conn.close()

    flagged_by = [name for name, hit in (("jev", jev and jev["malicious"]), ("nano", nano["malicious"]),
                                         ("patch", rule_hit is not None)) if hit]
    if rule_hit is not None:
        reason = "rule_match"
    elif jev is None:
        reason = "nano_only_jev_unavailable"
    elif {"jev", "nano"} <= set(flagged_by):
        reason = "jev_and_nano"
    elif flagged_by:
        reason = f"{flagged_by[0]}_only"
    else:
        reason = "jev_and_nano_clear"

    return {
        "decision": "malicious" if flagged_by else "safe",
        "nano_score": nano["score"],
        "jev_score": jev["score"] if jev else None,
        "jev_attack_type": jev.get("attack_type") if jev else None,
        "jev_latency_ms": jev.get("latency_ms") if jev else None,
        "jev_error": jev_error,
        "flagged_by": flagged_by,
        "reason": reason,
        "rule_id": rule_hit["id"] if rule_hit else None,
        # The field the classifier found most suspicious -- what a patch should target.
        "worst_field": list(field_inputs)[nano.get("worst_input_index", 0)],
    }
