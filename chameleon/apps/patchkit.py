"""Runtime for the code patches rendered into the demo apps.

Each app file declares `patches = PatchSet()` and calls `patches.check({...})`
at the top of its handler. chameleon.patch.integrate writes the approved
patches between the app's AUTO-PATCHES markers as small decorated functions:

    @patches.guard(rule_id='sqli-5', fields=('username',), ...)
    def sqli_5_ed282c48(value: str) -> bool:
        return deny(PATTERN, normalize(value))

The matching semantics are the same as the front door's (chameleon.patch.rules):
URL-decode repeatedly and lowercase for normalize_then_deny rules, and a regex
timeout that counts as a match, so a pathological input fails closed.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from typing import Callable

import regex
from fastapi import HTTPException

MATCH_TIMEOUT_S = 0.05


def normalize(text: str) -> str:
    prev = None
    while prev != text:
        prev = text
        text = urllib.parse.unquote(text)
    return text.lower()


def deny(pattern: str, text: str) -> bool:
    """True if the pattern matches. A timeout counts as a match (fail closed)."""
    try:
        return regex.search(pattern, text, regex.IGNORECASE, timeout=MATCH_TIMEOUT_S) is not None
    except TimeoutError:
        return True


@dataclass(frozen=True)
class Guard:
    fn: Callable[[str], bool]
    rule_id: str
    patch_id: str
    attack_type: str
    fields: tuple[str, ...]
    learned_from: str = ""
    description: str = ""

    def applies_to(self, field: str) -> bool:
        return "*" in self.fields or field in self.fields


class PatchSet:
    def __init__(self) -> None:
        self.guards: list[Guard] = []

    def guard(self, *, rule_id: str, patch_id: str, attack_type: str, fields: tuple[str, ...],
              learned_from: str = "", description: str = ""):
        def register(fn: Callable[[str], bool]) -> Callable[[str], bool]:
            self.guards.append(Guard(fn, rule_id, patch_id, attack_type, tuple(fields), learned_from, description))
            return fn
        return register

    def first_match(self, inputs: dict[str, str]) -> Guard | None:
        for g in self.guards:
            for field, value in inputs.items():
                if g.applies_to(field) and g.fn(value):
                    return g
        return None

    def check(self, inputs: dict[str, str]) -> None:
        """Raise 403 if any installed code patch blocks one of these inputs."""
        g = self.first_match(inputs)
        if g:
            raise HTTPException(status_code=403, detail={
                "error": "blocked by code patch", "rule_id": g.rule_id,
                "patch_id": g.patch_id, "attack_type": g.attack_type,
            })
