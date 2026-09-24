from chameleon import db, fusion, router


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


def test_malicious_request_routes_to_pending_honeypot(tmp_path, monkeypatch):
    monkeypatch.setattr(fusion, "decide", _fake_decide_factory("malicious"))
    conn = db.get_connection(tmp_path / "router.db")

    result = router.handle_request({"q": "1 union select null--"}, conn=conn)

    assert result["routed_to"] == "honeypot_pending"
    row = conn.execute("SELECT * FROM requests WHERE id = ?", (result["request_id"],)).fetchone()
    assert row["decision"] == "malicious"
