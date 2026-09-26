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
    assert "NanoPot" in resp.text


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
    monkeypatch.setattr(router, "handle_request", lambda fields, **kw: {
        "decision": "malicious", "reason": "nano_only_jev_unavailable", "nano_score": 0.98,
        "rule_id": None, "routed_to": "honeypot", "honeypot_reply": None, "session_id": "s-1"})
    import httpx
    from chameleon.api import main as api_main
    seen = {}

    def _fake_get(url, params=None, timeout=None, headers=None):
        seen.update(url=url, headers=headers)
        return httpx.Response(200, text='{"results": "id | username | password_sha1"}')

    monkeypatch.setattr(api_main.httpx, "get", _fake_get)
    body = client.post("/api/try", json={"target": "search", "inputs": {"q": "1 union select null--"}}).json()

    assert body["routed_to"] == "honeypot"
    assert seen["url"] == "http://127.0.0.1:8300/search" and seen["headers"] == {"X-Chameleon-Session": "s-1"}
    assert body["honeypot_reply"] == "id | username | password_sha1"
    assert "app_response" not in body


def test_try_forwards_safe_input_to_the_app_and_flags_canary_leaks(tmp_path, monkeypatch):
    import httpx
    from chameleon import router
    from chameleon.api import main as api_main
    client = _client(tmp_path, monkeypatch)
    monkeypatch.setattr(router, "handle_request", lambda fields, **kw: {
        "decision": "safe", "reason": "nano_only_jev_unavailable", "nano_score": 0.16,
        "rule_id": None, "routed_to": "app", "honeypot_reply": None})
    seen = {}

    def _fake_get(url, params=None, timeout=None, **kw):
        seen.update(url=url, params=params)
        return httpx.Response(200, text='{"content": "root:x:0:0 api_key=CANARY-APIKEY-x"}')

    monkeypatch.setattr(api_main.httpx, "get", _fake_get)
    body = client.post("/api/try", json={"target": "files", "inputs": {"name": "../../etc/passwd"}}).json()

    assert seen["url"].endswith("/files") and seen["params"] == {"name": "../../etc/passwd"}
    assert body["app_response"]["canary_leaked"] is True


def test_try_rejects_unknown_target_or_field(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    assert client.post("/api/try", json={"target": "shell", "inputs": {"q": "x"}}).status_code == 422
    assert client.post("/api/try", json={"target": "search", "inputs": {"cmd": "x"}}).status_code == 422
    assert client.post("/api/try", json={"target": "search", "inputs": {"q": "  "}}).status_code == 422


def test_try_login_checks_both_fields_and_forwards_as_json(tmp_path, monkeypatch):
    import httpx
    from chameleon import router
    from chameleon.api import main as api_main
    client = _client(tmp_path, monkeypatch)
    judged = {}
    monkeypatch.setattr(router, "handle_request", lambda fields, **kw: judged.update(fields) or {
        "decision": "safe", "reason": "r", "nano_score": 0.02, "rule_id": None,
        "routed_to": "app", "honeypot_reply": None, "session_id": None})
    sent = {}

    def _fake_post(url, json=None, timeout=None, **kw):
        sent.update(url=url, json=json)
        return httpx.Response(200, text='{"ok": false}')

    monkeypatch.setattr(api_main.httpx, "post", _fake_post)
    body = client.post("/api/try", json={"target": "login", "inputs": {"username": "jsmith"}}).json()

    assert judged == {"username": "jsmith", "password": ""}
    assert sent["url"].endswith("/login") and sent["json"] == {"username": "jsmith", "password": ""}
    assert body["app_response"]["status"] == 200


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

    assert client.post("/api/demo/reset").json()["ok"] is True
    assert client.get("/api/patches").json() == []
    assert client.get("/api/sessions").json() == []


def _wait_for_wave(client, timeout=5.0):
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        st = client.get("/api/scenario/status").json()
        if st["state"] != "running":
            return st
        time.sleep(0.02)
    raise AssertionError("wave never finished")


def test_attack_wave_runs_in_background_and_reports_progress(tmp_path, monkeypatch):
    import threading
    from chameleon.api import main as api_main
    from chameleon.redteam import scenario
    client = _client(tmp_path, monkeypatch)
    release = threading.Event()

    def _fake_run(conn, data_dir, on_progress=None):
        on_progress("wave 1: novel path traversal (10 requests)")
        release.wait(5)
        return {"events": [1, 2], "wave1_detection_rate": 0.0, "wave2_detection_rate": 0.7,
                "patch_result": {"status": "approved"}}

    monkeypatch.setattr(scenario, "run", _fake_run)
    monkeypatch.setitem(api_main._wave, "state", "idle")

    assert client.post("/api/scenario/start").json()["state"] == "running"
    assert client.post("/api/scenario/start").status_code == 409  # one wave at a time
    assert client.post("/api/demo/reset").status_code == 409      # no reset mid-wave
    import time
    for _ in range(250):  # the thread reports its first phase asynchronously
        if "wave 1" in (client.get("/api/scenario/status").json()["phase"] or ""):
            break
        time.sleep(0.02)
    assert "wave 1" in client.get("/api/scenario/status").json()["phase"]

    release.set()
    st = _wait_for_wave(client)
    assert st["state"] == "done" and st["result"]["wave2_detection_rate"] == 0.7


def test_attack_wave_errors_are_reported_not_swallowed(tmp_path, monkeypatch):
    from chameleon.api import main as api_main
    from chameleon.redteam import scenario
    client = _client(tmp_path, monkeypatch)

    def _boom(conn, data_dir, on_progress=None):
        raise RuntimeError("writer model unreachable")

    monkeypatch.setattr(scenario, "run", _boom)
    monkeypatch.setitem(api_main._wave, "state", "idle")

    client.post("/api/scenario/start")
    st = _wait_for_wave(client)
    assert st["state"] == "error" and "writer model unreachable" in st["error"]
