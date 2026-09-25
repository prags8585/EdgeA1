"""End-to-end patch pipeline: write -> deterministic tests -> verifier -> store.

Retries the writer with the specific failure reason, up to max_retries times.
A patch is marked 'approved' only after ALL three checks pass; every
intermediate attempt is recorded (patches + patch_events) so "verifier
rejected what the writer thought was good" can be measured later.
"""
from __future__ import annotations

from . import store
from . import tests as patch_tests
from . import verifier as patch_verifier
from . import writer as patch_writer


def _sample(items: list[str], n: int = 10) -> str:
    shown = ", ".join(repr(i) for i in items[:n])
    return shown + (f" (and {len(items) - n} more)" if len(items) > n else "")


def run(
    conn,
    *,
    attack_type: str,
    attack_payloads: list[str],
    benign_examples: list[str],
    writer_model: str,
    field: str = "q",
    max_retries: int = 3,
) -> dict:
    feedback = None
    patch_id = None
    rule = None

    for attempt in range(1, max_retries + 1):
        rule = patch_writer.write_rule(
            attack_type, attack_payloads, benign_examples,
            rule_id=f"{attack_type}-{attempt}", feedback=feedback, field=field,
        )
        patch_id = store.propose(conn, rule, writer_model)

        missed = patch_tests.missed_payloads(rule, attack_payloads, field=field)
        store.log_event(conn, patch_id, "replay_test", "fail" if missed else "pass",
                         f"did not block {len(missed)}/{len(attack_payloads)} attack payloads" if missed else None)
        if missed:
            store.set_status(conn, patch_id, "rejected")
            feedback = (
                f"The rule did not block {len(missed)} of the {len(attack_payloads)} attack payloads on replay. "
                f"Your pattern was {rule['pattern']!r}. It missed: {_sample(missed)}"
            )
            continue

        wrongly_blocked = patch_tests.false_positives(rule, benign_examples, field=field)
        if wrongly_blocked:
            fpr = len(wrongly_blocked) / len(benign_examples)
            store.log_event(conn, patch_id, "normal_traffic_test", "fail",
                             f"false positive rate {fpr:.2%} on benign traffic")
            store.set_status(conn, patch_id, "rejected")
            feedback = (
                f"The rule blocked {fpr:.0%} of benign traffic; it must not block real users. "
                f"Your pattern was {rule['pattern']!r}. It wrongly blocked: {_sample(wrongly_blocked)}"
            )
            continue
        store.log_event(conn, patch_id, "normal_traffic_test", "pass")

        slow_input = patch_tests.redos_offender(rule)
        if slow_input is not None:
            store.log_event(conn, patch_id, "redos_test", "fail", f"timed out on {slow_input[:40]!r}...")
            store.set_status(conn, patch_id, "rejected")
            feedback = (
                f"Your pattern {rule['pattern']!r} took too long on a long input starting "
                f"{slow_input[:40]!r} (catastrophic backtracking). Avoid nested or overlapping "
                "quantifiers like (a+)+, (\\w+\\s?)*, or (.*x){n}."
            )
            continue
        store.log_event(conn, patch_id, "redos_test", "pass")

        verdict = patch_verifier.verify(rule, attack_payloads[:5])
        store.log_event(conn, patch_id, "verifier", "pass" if verdict["approved"] else "fail",
                         "; ".join(verdict["reasons"]) or None)
        if not verdict["approved"]:
            store.set_status(conn, patch_id, "rejected")
            feedback = "Verifier rejected: " + "; ".join(verdict["reasons"])
            continue

        store.set_status(conn, patch_id, "approved")
        return {"patch_id": patch_id, "rule": rule, "status": "approved", "attempts": attempt}

    return {"patch_id": patch_id, "rule": rule, "status": "rejected", "attempts": max_retries, "feedback": feedback}
