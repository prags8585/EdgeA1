"""Input-validation rule engine: the v1 patch format.

A rule is {"id", "field": "*" | name, "type": "regex_deny" | "normalize_then_deny",
"pattern", "description", "attack_type"}. "field": "*" applies to every input.
Used both by the demo app (to enforce approved patches) and by the patch
pipeline's replay/normal-traffic tests.
"""
from __future__ import annotations

import re
import urllib.parse


def _normalize(text: str) -> str:
    # Repeated decode catches double-encoded payloads (e.g. %252e%252e).
    prev = None
    while prev != text:
        prev = text
        text = urllib.parse.unquote(text)
    return text.lower()


def matches(rule: dict, field: str, value: str) -> bool:
    if rule["field"] != "*" and rule["field"] != field:
        return False
    text = _normalize(value) if rule["type"] == "normalize_then_deny" else value
    return re.search(rule["pattern"], text, re.IGNORECASE) is not None


def blocked_by(rules: list[dict], inputs: dict[str, str]) -> dict | None:
    """Return the first rule that blocks any input, or None."""
    for rule in rules:
        for field, value in inputs.items():
            if matches(rule, field, value):
                return rule
    return None
