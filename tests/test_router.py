from chameleon import db, fusion, router
from chameleon.honeypot import session as honeypot_session


def _fake_decide_factory(decision: str):
    def _decide(inputs):
        return {"decision": decision, "nano_score": 0.9 if decision == "malicious" else 0.02,
                "jev_score": None, "reason": "test"}
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
    conn = db.get_connection(tmp_path / "router.db")

    result = router.handle_request({"q": "1 union select null--"}, conn=conn)

    assert result["routed_to"] == "honeypot"
    assert result["honeypot_reply"] == "fake reply from the honeypot"
    assert result["session_id"] is not None
    row = conn.execute("SELECT * FROM requests WHERE id = ?", (result["request_id"],)).fetchone()
    assert row["decision"] == "malicious"
    session_row = conn.execute("SELECT * FROM sessions WHERE id = ?", (result["session_id"],)).fetchone()
    assert session_row["status"] == "open"
