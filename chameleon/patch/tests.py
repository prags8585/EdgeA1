"""Deterministic checks a candidate patch must pass before the verifier sees it.

Two AIs (writer and verifier) can both be wrong; these tests are hard,
repeatable proof that doesn't depend on either model's opinion.
"""
from __future__ import annotations

from . import rules


def replay_test(rule: dict, attack_payloads: list[str], field: str = "q") -> bool:
    """The rule must block every captured attack payload."""
    return all(rules.blocked_by([rule], {field: p}) is not None for p in attack_payloads)


def normal_traffic_test(
    rule: dict, benign_texts: list[str], field: str = "q", max_fpr: float = 0.0
) -> tuple[bool, float]:
    """The rule must not block (more than max_fpr of) real traffic. Returns (passed, fpr)."""
    if not benign_texts:
        return True, 0.0
    blocked = sum(1 for t in benign_texts if rules.blocked_by([rule], {field: t}) is not None)
    fpr = blocked / len(benign_texts)
    return fpr <= max_fpr, fpr
