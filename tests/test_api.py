from fastapi.testclient import TestClient

from chameleon import config
from chameleon.api.main import app


def _client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "api.db")
    return TestClient(app)


def test_dashboard_serves_html(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Chameleon" in resp.text


def test_summary_on_empty_db(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    resp = client.get("/api/summary")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_requests"] == 0
    assert body["patches_by_status"] == {}
    assert body["calls_by_provider"] == {}


def test_requests_sessions_patches_empty_lists(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    assert client.get("/api/requests").json() == []
    assert client.get("/api/sessions").json() == []
    assert client.get("/api/patches").json() == []
    assert client.get("/api/llm_calls").json() == []


def test_reset_demo_clears_tables(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)

    from chameleon import db
    conn = db.get_connection(tmp_path / "api.db")
    db.init_db(conn)
    db.log_llm_call(conn, provider="nano", model="writer", role="honeypot", latency_ms=1.0)
    conn.close()

    assert client.get("/api/llm_calls").json() != []
    resp = client.post("/api/demo/reset")
    assert resp.status_code == 200
    assert client.get("/api/llm_calls").json() == []


def test_try_routes_malicious_input_to_honeypot(tmp_path, monkeypatch):
    from chameleon import router
    client = _client(tmp_path, monkeypatch)
    monkeypatch.setattr(router, "handle_request", lambda fields: {
        "decision": "malicious", "reason": "nano_only_jev_unavailable", "nano_score": 0.98,
        "rule_id": None, "routed_to": "honeypot", "honeypot_reply": "Invalid search query."})

    body = client.post("/api/try", json={"field": "q", "value": "1 union select null--"}).json()

    assert body["routed_to"] == "honeypot"
    assert body["honeypot_reply"] == "Invalid search query."
    assert "app_response" not in body


def test_try_forwards_safe_input_to_the_app_and_flags_canary_leaks(tmp_path, monkeypatch):
    import httpx
    from chameleon import router
    from chameleon.api import main as api_main
    client = _client(tmp_path, monkeypatch)
    monkeypatch.setattr(router, "handle_request", lambda fields: {
        "decision": "safe", "reason": "nano_only_jev_unavailable", "nano_score": 0.16,
        "rule_id": None, "routed_to": "app", "honeypot_reply": None})
    seen = {}

    def _fake_get(url, params=None, timeout=None):
        seen.update(url=url, params=params)
        return httpx.Response(200, text='{"content": "root:x:0:0 api_key=CANARY-APIKEY-x"}')

    monkeypatch.setattr(api_main.httpx, "get", _fake_get)
    body = client.post("/api/try", json={"field": "name", "value": "../../etc/passwd"}).json()

    assert seen["url"].endswith("/files") and seen["params"] == {"name": "../../etc/passwd"}
    assert body["app_response"]["canary_leaked"] is True


def test_try_rejects_unknown_field(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    assert client.post("/api/try", json={"field": "cmd", "value": "x"}).status_code == 422


def test_reset_clears_linked_rows_without_foreign_key_errors(tmp_path, monkeypatch):
    # Regression: reset used to delete sessions/patches before their child rows,
    # which fails once a real scenario has populated attack_events/patch_events.
    from chameleon import db
    from chameleon.honeypot import session as honeypot_session
    from chameleon.patch import store
    client = _client(tmp_path, monkeypatch)
    conn = db.get_connection(tmp_path / "api.db")
    db.init_db(conn)
    sid = honeypot_session.start_session(conn=conn)
    honeypot_session._log_attack_event(conn, sid, "q", "1 union select null--")
    pid = store.propose(conn, {"id": "r", "field": "*", "type": "regex_deny", "pattern": "x",
                               "description": "d", "attack_type": "sqli"}, "writer")
    store.log_event(conn, pid, "replay_test", "pass")
    store.set_status(conn, pid, "approved")
    conn.close()

    assert client.post("/api/demo/reset").json() == {"ok": True}
    assert client.get("/api/patches").json() == []
    assert client.get("/api/sessions").json() == []
