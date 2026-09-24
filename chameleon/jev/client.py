"""Client for TypeSafe AI's Jev cloud check API.

Access is still pending (waitlist, see HANDOFF.md section 6.5): the exact
endpoint, auth header, and request schema aren't known yet. Until then this
raises JevUnavailable, which chameleon.fusion treats as a first-class case
(fall back to the Nano check model alone) rather than an error.
"""
from __future__ import annotations

from .. import config


class JevUnavailable(Exception):
    pass


def check(inputs: list[str]) -> dict:
    """Returns {"malicious": bool, "score": float}, or raises JevUnavailable."""
    if not config.JEV_API_KEY or not config.JEV_API_URL:
        raise JevUnavailable("JEV_API_KEY/JEV_API_URL not configured")
    # Fill in once we have Jev's real API docs (endpoint, auth, request/response schema).
    raise JevUnavailable("Jev client not yet implemented")
