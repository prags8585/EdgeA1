"""Deterministic checks a candidate patch must pass before the verifier sees it.

Two AIs (writer and verifier) can both be wrong; these tests are hard,
repeatable proof that doesn't depend on either model's opinion.
"""
from __future__ import annotations

from . import rules


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
