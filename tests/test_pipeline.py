from chameleon import db
from chameleon.patch import pipeline
from chameleon.patch import verifier as patch_verifier
from chameleon.patch import writer as patch_writer

GOOD_RULE = {
    "id": "sqli-1", "field": "q", "type": "normalize_then_deny",
    "pattern": r"union\s+select", "description": "blocks sqli", "attack_type": "sqli",
}
USELESS_RULE = {
    "id": "sqli-x", "field": "q", "type": "regex_deny",
    "pattern": r"this-never-matches-anything-zzz", "description": "bad", "attack_type": "sqli",
}

ATTACK_PAYLOADS = ["1 union select null--", "2 UNION SELECT username, password FROM users--"]
BENIGN = ["blue shirt", "search for shoes"]


def _conn(tmp_path):
    conn = db.get_connection(tmp_path / "pipeline.db")
    db.init_db(conn)
    return conn


def test_pipeline_approves_a_good_rule_on_first_attempt(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    monkeypatch.setattr(patch_writer, "write_rule", lambda *a, **k: GOOD_RULE)
    monkeypatch.setattr(patch_verifier, "verify", lambda *a, **k: {"approved": True, "reasons": [], "risks": []})

    result = pipeline.run(
        conn, attack_type="sqli", attack_payloads=ATTACK_PAYLOADS,
        benign_examples=BENIGN, writer_model="writer-model",
    )

    assert result["status"] == "approved"
    assert result["attempts"] == 1
    row = conn.execute("SELECT status FROM patches WHERE id = ?", (result["patch_id"],)).fetchone()
    assert row["status"] == "approved"


def test_pipeline_retries_after_failed_replay_test_then_succeeds(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    rules_in_order = [USELESS_RULE, GOOD_RULE]
    monkeypatch.setattr(patch_writer, "write_rule", lambda *a, **k: rules_in_order.pop(0))
    monkeypatch.setattr(patch_verifier, "verify", lambda *a, **k: {"approved": True, "reasons": [], "risks": []})

    result = pipeline.run(
        conn, attack_type="sqli", attack_payloads=ATTACK_PAYLOADS,
        benign_examples=BENIGN, writer_model="writer-model", max_retries=3,
    )

    assert result["status"] == "approved"
    assert result["attempts"] == 2
    statuses = [r["status"] for r in conn.execute("SELECT status FROM patches ORDER BY created_at")]
    assert statuses == ["rejected", "approved"]


def test_pipeline_gives_up_after_max_retries(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    monkeypatch.setattr(patch_writer, "write_rule", lambda *a, **k: USELESS_RULE)
    monkeypatch.setattr(patch_verifier, "verify", lambda *a, **k: {"approved": True, "reasons": [], "risks": []})

    result = pipeline.run(
        conn, attack_type="sqli", attack_payloads=ATTACK_PAYLOADS,
        benign_examples=BENIGN, writer_model="writer-model", max_retries=2,
    )

    assert result["status"] == "rejected"
    assert result["attempts"] == 2
    assert "did not block" in result["feedback"]


def test_retry_feedback_names_the_payloads_the_rule_missed(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    feedback_seen = []

    def _write_rule(*a, feedback=None, **k):
        feedback_seen.append(feedback)
        return USELESS_RULE if len(feedback_seen) == 1 else GOOD_RULE

    monkeypatch.setattr(patch_writer, "write_rule", _write_rule)
    monkeypatch.setattr(patch_verifier, "verify", lambda *a, **k: {"approved": True, "reasons": [], "risks": []})

    pipeline.run(
        conn, attack_type="sqli", attack_payloads=ATTACK_PAYLOADS,
        benign_examples=BENIGN, writer_model="writer-model",
    )

    assert feedback_seen[0] is None
    assert repr(ATTACK_PAYLOADS[0]) in feedback_seen[1]
    assert USELESS_RULE["pattern"] in feedback_seen[1]


def test_retry_feedback_accumulates_every_earlier_failure(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    feedback_seen = []

    def _write_rule(*a, feedback=None, **k):
        feedback_seen.append(feedback)
        return USELESS_RULE

    monkeypatch.setattr(patch_writer, "write_rule", _write_rule)
    pipeline.run(
        conn, attack_type="sqli", attack_payloads=ATTACK_PAYLOADS,
        benign_examples=BENIGN, writer_model="writer-model", max_retries=3,
    )

    assert "Attempt 1:" in feedback_seen[2] and "Attempt 2:" in feedback_seen[2]


def test_pipeline_rejects_redos_prone_rule_before_the_verifier_sees_it(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    # Blocks the attacks, passes normal traffic -- but backtracks catastrophically.
    redos_rule = {**GOOD_RULE, "id": "sqli-redos", "pattern": r"union\s+select|(\w|\d)+!$"}
    rules_in_order = [redos_rule, GOOD_RULE]
    feedback_seen = []

    def _write_rule(*a, feedback=None, **k):
        feedback_seen.append(feedback)
        return rules_in_order.pop(0)

    verified = []
    monkeypatch.setattr(patch_writer, "write_rule", _write_rule)
    monkeypatch.setattr(patch_verifier, "verify",
                        lambda rule, *a, **k: verified.append(rule) or {"approved": True, "reasons": [], "risks": []})

    result = pipeline.run(
        conn, attack_type="sqli", attack_payloads=ATTACK_PAYLOADS,
        benign_examples=BENIGN, writer_model="writer-model",
    )

    assert result["status"] == "approved" and result["attempts"] == 2
    assert verified == [GOOD_RULE]
    assert "backtracking" in feedback_seen[1]


def test_pipeline_rejects_rule_bypassed_by_url_encoding(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    raw_rule = {**GOOD_RULE, "id": "sqli-raw", "type": "regex_deny"}
    rules_in_order = [raw_rule, GOOD_RULE]
    feedback_seen = []

    def _write_rule(*a, feedback=None, **k):
        feedback_seen.append(feedback)
        return rules_in_order.pop(0)

    monkeypatch.setattr(patch_writer, "write_rule", _write_rule)
    monkeypatch.setattr(patch_verifier, "verify", lambda *a, **k: {"approved": True, "reasons": [], "risks": []})

    result = pipeline.run(
        conn, attack_type="sqli", attack_payloads=ATTACK_PAYLOADS,
        benign_examples=BENIGN, writer_model="writer-model",
    )

    assert result["status"] == "approved" and result["attempts"] == 2
    assert "normalize_then_deny" in feedback_seen[1]


def test_verifier_receives_measured_facts(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    captured = {}
    monkeypatch.setattr(patch_writer, "write_rule", lambda *a, **k: GOOD_RULE)
    monkeypatch.setattr(patch_verifier, "verify",
                        lambda rule, sample, measurements=None: captured.update(measurements) or
                        {"approved": True, "reasons": [], "risks": []})

    pipeline.run(conn, attack_type="sqli", attack_payloads=ATTACK_PAYLOADS,
                 benign_examples=BENIGN, writer_model="writer-model")

    assert captured["false_positives_on_benign_sample"] == f"0 of {len(BENIGN)}"
    assert captured["worst_case_match_ms_on_2kb_adversarial_inputs"] < captured["runtime_budget_ms"]


def _verifier_says(**verdict):
    base = {"approved": False, "reasons": [], "risks": [], "bypass_examples": [], "false_positive_examples": []}
    return lambda *a, **k: {**base, **verdict}


def test_unsubstantiated_verifier_rejection_is_overridden(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    monkeypatch.setattr(patch_writer, "write_rule", lambda *a, **k: GOOD_RULE)
    # Objects, but its "false positive" is not actually blocked by the rule.
    monkeypatch.setattr(patch_verifier, "verify", _verifier_says(
        reasons=["pattern too broad"], false_positive_examples=["blue shirt"]))

    result = pipeline.run(conn, attack_type="sqli", attack_payloads=ATTACK_PAYLOADS,
                          benign_examples=BENIGN, writer_model="writer-model", max_retries=1)

    assert result["status"] == "approved"
    event = conn.execute("SELECT result, reason FROM patch_events WHERE stage='verifier'").fetchone()
    assert event["result"] == "overridden" and "pattern too broad" in event["reason"]


def test_confirmed_false_positive_from_verifier_rejects(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    monkeypatch.setattr(patch_writer, "write_rule", lambda *a, **k: GOOD_RULE)
    # "please union select my favorites" really is blocked by GOOD_RULE.
    monkeypatch.setattr(patch_verifier, "verify", _verifier_says(
        false_positive_examples=["please union select my favorites"]))

    result = pipeline.run(conn, attack_type="sqli", attack_payloads=ATTACK_PAYLOADS,
                          benign_examples=BENIGN, writer_model="writer-model", max_retries=2)

    assert result["status"] == "rejected"
    assert "union select my favorites" in result["feedback"]


def test_confirmed_bypass_retries_then_approves_best_with_known_bypasses(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    monkeypatch.setattr(patch_writer, "write_rule", lambda *a, **k: GOOD_RULE)
    # A real bypass the rule misses, every attempt.
    monkeypatch.setattr(patch_verifier, "verify", _verifier_says(bypass_examples=["1 UNION/**/SELECT null"]))

    result = pipeline.run(conn, attack_type="sqli", attack_payloads=ATTACK_PAYLOADS,
                          benign_examples=BENIGN, writer_model="writer-model", max_retries=2)

    assert result["status"] == "approved"
    assert result["known_bypasses"] == ["1 UNION/**/SELECT null"]
    assert conn.execute("SELECT COUNT(*) AS n FROM patches WHERE status='approved'").fetchone()["n"] == 1
