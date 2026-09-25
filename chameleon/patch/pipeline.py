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
    max_retries: int = 5,
) -> dict:
    feedback = None
    history: list[str] = []
    patch_id = None
    rule = None

    for attempt in range(1, max_retries + 1):
        # The writer sees every earlier failure, not just the last one -- with only
        # the latest feedback it was observed fixing one problem and regressing on
        # another it had already solved.
        if feedback:
            history.append(feedback)
        rule = patch_writer.write_rule(
            attack_type, attack_payloads, benign_examples,
            rule_id=f"{attack_type}-{attempt}", field=field,
            feedback="\n\n".join(f"Attempt {k}: {h}" for k, h in enumerate(history, 1)) or None,
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

        bypassed = patch_tests.encoding_bypasses(rule, attack_payloads, field=field)
        store.log_event(conn, patch_id, "encoding_test", "fail" if bypassed else "pass",
                         f"URL-encoded forms of {len(bypassed)} payloads slip through" if bypassed else None)
        if bypassed:
            store.set_status(conn, patch_id, "rejected")
            feedback = (
                f"Your pattern {rule['pattern']!r} (type {rule['type']!r}) blocks the raw payloads but not "
                f"their URL-encoded forms, e.g. {patch_tests.url_encode_all(bypassed[0])!r}. Attackers "
                "routinely encode. Use type \"normalize_then_deny\": it URL-decodes the input repeatedly "
                "and lowercases it before matching, so write the pattern against decoded, lowercase text."
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
                f"Your pattern {rule['pattern']!r} exceeded the 50 ms budget on a "
                f"{len(slow_input)}-character input of repeated {slow_input[:3]!r} (backtracking). "
                "Avoid nested or overlapping quantifiers like (a+)+, (\\w|\\d)+, or (.*x){n}, and "
                "open-ended repeats like \\.{2,} next to other quantified groups; match fixed tokens "
                "(like \\.\\./) instead."
            )
            continue
        store.log_event(conn, patch_id, "redos_test", "pass")

        measurements = {
            "blocks_all_captured_payloads": True,
            "blocks_url_encoded_forms_of_captured_payloads": True,
            "false_positives_on_benign_sample": f"0 of {len(benign_examples)}",
            "worst_case_match_ms_on_2kb_adversarial_inputs": patch_tests.worst_case_ms(rule),
            "runtime_budget_ms": patch_tests.REDOS_BUDGET_S * 1000,
        }
        verdict = patch_verifier.verify(rule, attack_payloads[:5], measurements)
        store.log_event(conn, patch_id, "verifier", "pass" if verdict["approved"] else "fail",
                         "; ".join(verdict["reasons"]) or None)
        if not verdict["approved"]:
            store.set_status(conn, patch_id, "rejected")
            feedback = "Verifier rejected: " + "; ".join(verdict["reasons"])
            continue

        store.set_status(conn, patch_id, "approved")
        return {"patch_id": patch_id, "rule": rule, "status": "approved", "attempts": attempt}

    return {"patch_id": patch_id, "rule": rule, "status": "rejected", "attempts": max_retries, "feedback": feedback}
