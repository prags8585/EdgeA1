from chameleon import autopatch, db, fusion, router
from chameleon.honeypot import session as honeypot_session


def _fake_decide_factory(decision: str):
    def _decide(field_inputs, conn=None):
        return {"decision": decision, "nano_score": 0.9 if decision == "malicious" else 0.02,
                "jev_score": None, "reason": "test", "rule_id": None}
    return _decide


def test_safe_request_routes_to_app_and_is_logged(tmp_path, monkeypatch):
    monkeypatch.setattr(fusion, "decide", _fake_decide_factory("safe"))
    conn = db.get_connection(tmp_path / "router.db")

    result = router.handle_request({"q": "blue shirt"}, conn=conn)

    assert result["routed_to"] == "app"
    row = conn.execute("SELECT * FROM requests WHERE id = ?", (result["request_id"],)).fetchone()
    assert row["decision"] == "safe"


def test_malicious_request_routes_to_honeypot_and_logs_the_session(tmp_path, monkeypatch):
    monkeypatch.setattr(fusion, "decide", _fake_decide_factory("malicious"))
    monkeypatch.setattr(honeypot_session, "respond", lambda *a, **k: "fake reply from the honeypot")
    queued = []
    monkeypatch.setattr(autopatch, "submit", lambda conn, field, payload, kind: queued.append((field, payload, kind)) or "job-1")
    conn = db.get_connection(tmp_path / "router.db")

    result = router.handle_request({"q": "1 union select null--"}, conn=conn)

    assert result["routed_to"] == "honeypot"
    assert result["patch_job_id"] == "job-1"
    assert queued == [("q", "1 union select null--", "sqli")]
    assert result["honeypot_reply"] == "fake reply from the honeypot"
    assert result["session_id"] is not None
    row = conn.execute("SELECT * FROM requests WHERE id = ?", (result["request_id"],)).fetchone()
    assert row["decision"] == "malicious"
    session_row = conn.execute("SELECT * FROM sessions WHERE id = ?", (result["session_id"],)).fetchone()
    assert session_row["status"] == "open"


def test_stolen_honeytoken_is_blocked_and_traced_to_its_session(tmp_path, monkeypatch):
    from chameleon.honeypot import deception
    monkeypatch.setattr(fusion, "decide", _fake_decide_factory("safe"))  # looks like a normal login
    conn = db.get_connection(tmp_path / "router.db")
    db.init_db(conn)
    creds = deception.issue(conn, "session-that-got-fooled")

    result = router.handle_request({"username": "admin", "password": creds["admin_password"]}, conn=conn)

    assert result["routed_to"] == "blocked"
    assert result["blocked"]["why"] == "stolen_honeytoken"
    assert result["blocked"]["leaked_to_session"] == "session-that-got-fooled"


def test_attack_matching_an_approved_patch_is_blocked_not_honeypotted(tmp_path, monkeypatch):
    def _decide(field_inputs, conn=None):
        return {"decision": "malicious", "nano_score": 0.9, "jev_score": None,
                "reason": "rule_match", "rule_id": "sqli-3", "worst_field": "q"}
    monkeypatch.setattr(fusion, "decide", _decide)
    monkeypatch.setattr(honeypot_session, "respond", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no honeypot")))
    conn = db.get_connection(tmp_path / "router.db")

    result = router.handle_request({"q": "1 union select null--"}, conn=conn)

    assert result["routed_to"] == "blocked" and result["blocked"] == {"why": "rule_match", "rule_id": "sqli-3"}
