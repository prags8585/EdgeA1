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
            rule_id=f"{attack_type}-{attempt}", feedback=feedback,
        )
        patch_id = store.propose(conn, rule, writer_model)

        replay_ok = patch_tests.replay_test(rule, attack_payloads, field=field)
        store.log_event(conn, patch_id, "replay_test", "pass" if replay_ok else "fail",
                         None if replay_ok else "did not block all attack payloads")
        if not replay_ok:
            store.set_status(conn, patch_id, "rejected")
            feedback = "The rule did not block all the attack payloads on replay."
            continue

        normal_ok, fpr = patch_tests.normal_traffic_test(rule, benign_examples, field=field)
        store.log_event(conn, patch_id, "normal_traffic_test", "pass" if normal_ok else "fail",
                         None if normal_ok else f"false positive rate {fpr:.2%} on benign traffic")
        if not normal_ok:
            store.set_status(conn, patch_id, "rejected")
            feedback = f"The rule blocked {fpr:.0%} of benign traffic; it must not block real users."
            continue

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
