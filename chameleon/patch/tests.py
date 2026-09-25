"""Deterministic checks a candidate patch must pass before the verifier sees it.

Two AIs (writer and verifier) can both be wrong; these tests are hard,
repeatable proof that doesn't depend on either model's opinion.
"""
from __future__ import annotations

import regex

from . import rules

# Long inputs built from the characters attack patterns tend to quantify over.
# A safe pattern handles every one well inside the budget.
ADVERSARIAL_INPUTS = [
    "a" * 10_000 + "!", "1" * 10_000 + "x", " " * 10_000 + "x", "word " * 2_000 + "!",
    "../" * 3_000 + "x", "." * 10_000 + "/", "/" * 10_000 + "x", "%2e" * 3_000 + "x",
    "<" * 10_000 + "x", "'" * 10_000 + "x", "-" * 10_000 + "x", "=" * 10_000 + "(",
]
REDOS_BUDGET_S = 0.1


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
