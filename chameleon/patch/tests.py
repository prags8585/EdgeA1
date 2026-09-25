"""Deterministic checks a candidate patch must pass before the verifier sees it.

Two AIs (writer and verifier) can both be wrong; these tests are hard,
repeatable proof that doesn't depend on either model's opinion.
"""
from __future__ import annotations

import time

import regex

from . import rules

# Two layers. At runtime, rules.MATCH_TIMEOUT_S caps what any pattern can cost
# per field and fails closed, so no input can hang the app. This patch-time
# check makes sure realistically sized inputs (up to ~2 KB per field, built from
# the characters attack patterns tend to quantify over) finish inside that same
# budget -- otherwise legitimate traffic would be rerouted by timeouts.
# Exponential patterns fail this at any length; merely quadratic ones fail only
# if they're too slow at realistic sizes. Measured on the Nano: a real writer
# pattern took 0.22s at 4,000 chars and 0.88s at 8,000 (4x per doubling).
REDOS_INPUT_CHARS = 2_048
ADVERSARIAL_INPUTS = [
    (unit * (REDOS_INPUT_CHARS // len(unit)))[:REDOS_INPUT_CHARS] + tail
    for unit, tail in [
        ("a", "!"), ("1", "x"), (" ", "x"), ("word ", "!"), ("../", "x"), (".", "x"),
        ("/", "x"), ("%2e", "x"), ("<", "x"), ("'", "x"), ("-", "x"), ("=", "("),
    ]
]
REDOS_BUDGET_S = rules.MATCH_TIMEOUT_S


def url_encode_all(text: str) -> str:
    """Percent-encode every non-alphanumeric byte -- including '.', which
    urllib's quote() leaves alone. This is what a double-encoded payload
    looks like after the web framework's single decode."""
    return "".join(c if c.isascii() and c.isalnum() else "".join(f"%{b:02x}" for b in c.encode()) for c in text)


def encoding_bypasses(rule: dict, attack_payloads: list[str], field: str = "q") -> list[str]:
    """Captured payloads whose URL-encoded form the rule fails to block."""
    return [p for p in attack_payloads if rules.blocked_by([rule], {field: url_encode_all(p)}) is None]


def worst_case_ms(rule: dict) -> float:
    """Slowest single match over ADVERSARIAL_INPUTS, for the verifier's facts."""
    worst = 0.0
    for text in ADVERSARIAL_INPUTS:
        start = time.perf_counter()
        try:
            regex.search(rule["pattern"], text, regex.IGNORECASE, timeout=REDOS_BUDGET_S)
        except TimeoutError:
            return REDOS_BUDGET_S * 1000
        worst = max(worst, (time.perf_counter() - start) * 1000)
    return round(worst, 2)


def redos_offender(rule: dict) -> str | None:
    """The first adversarial input the pattern can't finish within budget, or None."""
    for text in ADVERSARIAL_INPUTS:
        try:
            regex.search(rule["pattern"], text, regex.IGNORECASE, timeout=REDOS_BUDGET_S)
        except TimeoutError:
            return text
    return None


def missed_payloads(rule: dict, attack_payloads: list[str], field: str = "q") -> list[str]:
    return [p for p in attack_payloads if rules.blocked_by([rule], {field: p}) is None]


def false_positives(rule: dict, benign_texts: list[str], field: str = "q") -> list[str]:
    return [t for t in benign_texts if rules.blocked_by([rule], {field: t}) is not None]


def replay_test(rule: dict, attack_payloads: list[str], field: str = "q") -> bool:
    """The rule must block every captured attack payload."""
    return not missed_payloads(rule, attack_payloads, field)


def normal_traffic_test(
    rule: dict, benign_texts: list[str], field: str = "q", max_fpr: float = 0.0
) -> tuple[bool, float]:
    """The rule must not block (more than max_fpr of) real traffic. Returns (passed, fpr)."""
    if not benign_texts:
        return True, 0.0
    fpr = len(false_positives(rule, benign_texts, field)) / len(benign_texts)
    return fpr <= max_fpr, fpr
