"""Input-validation rule engine: the v1 patch format.

A rule is {"id", "field": "*" | name, "type": "regex_deny" | "normalize_then_deny",
"pattern", "description", "attack_type"}. "field": "*" applies to every input.
Used both by the demo app and the check layer (to enforce approved patches)
and by the patch pipeline's tests.

Patterns are written by a model and then run against every live request, so a
catastrophically-backtracking pattern would let the security layer itself be
used for denial of service. Two defenses: the third-party `regex` engine (which
avoids the exponential blowups stdlib `re` hits on patterns like `^(\\d+)*$`),
and a hard per-match timeout that fails closed.
"""
from __future__ import annotations

import urllib.parse

import regex

MATCH_TIMEOUT_S = 0.05


def _normalize(text: str) -> str:
    # Repeated decode catches double-encoded payloads (e.g. %252e%252e).
    prev = None
    while prev != text:
        prev = text
        text = urllib.parse.unquote(text)
    return text.lower()


def search(pattern: str, text: str) -> bool:
    """True if pattern matches. A timeout counts as a match (fail closed)."""
    try:
        return regex.search(pattern, text, regex.IGNORECASE, timeout=MATCH_TIMEOUT_S) is not None
    except TimeoutError:
        return True


def matches(rule: dict, field: str, value: str) -> bool:
    if rule["field"] != "*" and rule["field"] != field:
        return False
    text = _normalize(value) if rule["type"] == "normalize_then_deny" else value
    return search(rule["pattern"], text)


def blocked_by(rules: list[dict], inputs: dict[str, str]) -> dict | None:
    """Return the first rule that blocks any input, or None."""
    for rule in rules:
        for field, value in inputs.items():
            if matches(rule, field, value):
                return rule
    return None
