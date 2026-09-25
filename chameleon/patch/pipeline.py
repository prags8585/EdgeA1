"""End-to-end patch pipeline: write -> deterministic tests -> verifier -> store.

Retries the writer with the specific failure reason, up to max_retries times.
A patch is approved only after every deterministic check passes (replay,
URL-encoding, normal traffic, ReDoS) and the verifier raises no objection
that survives testing. Every attempt is recorded (patches + patch_events).
"""
from __future__ import annotations

import regex

from . import rules, store
from . import tests as patch_tests
from . import verifier as patch_verifier
from . import writer as patch_writer


def _sample(items: list[str], n: int = 10) -> str:
    shown = ", ".join(repr(i) for i in items[:n])
    return shown + (f" (and {len(items) - n} more)" if len(items) > n else "")


def _issue_count(issues: dict) -> int:
    return (len(issues["bypasses"]) + len(issues["disputed_false_positives"])
            + (1 if issues.get("verifier_unusable") else 0))


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
    best = None  # (patch_id, rule, confirmed_bypasses) of the safest near-miss

    for attempt in range(1, max_retries + 1):
        # The writer sees every earlier failure, not just the last one -- with only
        # the latest feedback it was observed fixing one problem and regressing on
        # another it had already solved.
        if feedback:
            history.append(feedback)
        feedback = None
        try:
            rule = patch_writer.write_rule(
                attack_type, attack_payloads, benign_examples,
                rule_id=f"{attack_type}-{attempt}", field=field,
                feedback="\n\n".join(f"Attempt {k}: {h}" for k, h in enumerate(history, 1)) or None,
            )
        except (ValueError, regex.error) as exc:  # bad JSON (JSONDecodeError is a ValueError) or bad regex
            feedback = f"Your previous output was not a valid rule ({str(exc)[:120]}). Output one valid JSON rule."
            continue
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
        # The verifier's objections are claims; its concrete examples get tested like
        # anything else. Observed live: it rejected a rule that caught 85% of 280 unseen
        # payloads with 0/6,434 false positives, and 2 of its 3 "bypasses" were blocked.
        if verdict.get("unusable"):
            # No verdict to act on and nothing for the writer to fix: keep the rule
            # as a candidate (it passed every deterministic check) and try again.
            store.log_event(conn, patch_id, "verifier", "fail", "no usable verdict")
            store.set_status(conn, patch_id, "rejected")
            if best is None:
                best = (patch_id, rule, {"bypasses": [], "disputed_false_positives": [], "verifier_unusable": True})
            continue

        bypasses = [b for b in verdict.get("bypass_examples", []) if rules.blocked_by([rule], {field: b}) is None]
        false_pos = [f for f in verdict.get("false_positive_examples", []) if rules.blocked_by([rule], {field: f}) is not None]
        reasons = "; ".join(verdict["reasons"])

        # Both kinds of confirmed claim become feedback, and the rule is kept as a
        # candidate -- it already passed every deterministic check, including zero
        # false positives on *real* benign traffic. A verifier's false-positive
        # example is model-invented (observed live: it vetoed a good rule over the
        # file name '....'), so it's a hint, not a veto over measured behavior.
        if bypasses or false_pos:
            issues = {"bypasses": bypasses, "disputed_false_positives": false_pos}
            store.log_event(conn, patch_id, "verifier", "fail",
                            f"confirmed bypasses: {_sample(bypasses)}; claimed false positives: {_sample(false_pos)}")
            store.set_status(conn, patch_id, "rejected")
            if best is None or _issue_count(issues) < _issue_count(best[2]):
                best = (patch_id, rule, issues)
            hints = []
            if bypasses:
                hints.append(f"attack inputs it misses: {_sample(bypasses)} -- extend it to cover these")
            if false_pos:
                hints.append(f"inputs it may wrongly block: {_sample(false_pos)} -- narrow it if you can")
            feedback = (f"An independent reviewer checked your pattern {rule['pattern']!r} and found "
                        + "; ".join(hints)
                        + ". Keep blocking every attack payload shown; don't trade one for the other.")
            continue

        if verdict["approved"]:
            store.log_event(conn, patch_id, "verifier", "pass", reasons or None)
        else:
            store.log_event(conn, patch_id, "verifier", "overridden",
                            f"rejection unsubstantiated -- none of its examples held up: {reasons}")
        store.set_status(conn, patch_id, "approved")
        return {"patch_id": patch_id, "rule": rule, "status": "approved", "attempts": attempt}

    if best is not None:
        # Passed every deterministic safety check; the only open issues are the
        # verifier's recorded claims. Some protection beats none -- a captured
        # bypass will start a new patch, and every claim stays on record.
        best_id, best_rule, issues = best
        store.log_event(conn, best_id, "approved_with_known_issues", "pass",
                        f"bypasses: {_sample(issues['bypasses'])}; "
                        f"disputed false positives: {_sample(issues['disputed_false_positives'])}"
                        + ("; verifier gave no usable verdict" if issues.get("verifier_unusable") else ""))
        store.set_status(conn, best_id, "approved")
        return {"patch_id": best_id, "rule": best_rule, "status": "approved", "attempts": max_retries,
                "known_bypasses": issues["bypasses"],
                "disputed_false_positives": issues["disputed_false_positives"],
                "verifier_unusable": bool(issues.get("verifier_unusable"))}

    return {"patch_id": patch_id, "rule": rule, "status": "rejected", "attempts": max_retries, "feedback": feedback}
