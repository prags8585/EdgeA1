"""Combine the Nano check model and Jev (when available) into one decision.

Malicious if either signal is confident. If Jev is unavailable, fall back
to the Nano model alone. Both scores are always returned so the caller can
log them -- the disagreement cases are the interesting evidence.
"""
from __future__ import annotations

import httpx

from . import config
from .jev import client as jev_client

JEV_THRESHOLD = 0.5


def check_nano(inputs: list[str]) -> dict:
    resp = httpx.post(f"{config.CHECK_MODEL_URL}/check", json={"inputs": inputs}, timeout=5.0)
    resp.raise_for_status()
    return resp.json()


def decide(inputs: list[str]) -> dict:
    nano = check_nano(inputs)

    jev_score = None
    jev_available = True
    try:
        jev = jev_client.check(inputs)
        jev_score = jev["score"]
    except jev_client.JevUnavailable:
        jev_available = False

    if jev_available:
        malicious = nano["malicious"] or jev_score >= JEV_THRESHOLD
        reason = "nano_or_jev"
    else:
        malicious = nano["malicious"]
        reason = "nano_only_jev_unavailable"

    return {
        "decision": "malicious" if malicious else "safe",
        "nano_score": nano["score"],
        "jev_score": jev_score,
        "reason": reason,
    }
