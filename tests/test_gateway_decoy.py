import httpx
from fastapi.testclient import TestClient

from chameleon import config, db, router
from chameleon.decoy import app as decoy
from chameleon.gateway import app as gateway
from chameleon.honeypot import session as honeypot_session


def _route(routed_to, **extra):
    return lambda fields, **kw: {"routed_to": routed_to, "session_id": "4b0f6a52-8f4f-4a55-9a5c-0d9f2c1e7a11",
                                 "blocked": None, **extra}


def test_attack_is_redirected_to_the_decoy_with_its_session_and_method_kept(monkeypatch):
    monkeypatch.setattr(router, "handle_request", _route("honeypot"))
    client = TestClient(gateway.app)

    resp = client.get("/search", params={"q": "1' union select 1--"}, follow_redirects=False)
    post = client.post("/login", json={"username": "admin' --", "password": "x"}, follow_redirects=False)

    assert resp.status_code == 307 and post.status_code == 307
    assert resp.headers["location"].startswith(f"{config.DECOY_APP_URL}/search?q=1%27+union+select+1--&cs=4b0f6a52")
    assert post.headers["location"].startswith(f"{config.DECOY_APP_URL}/login?cs=")


def test_stolen_credentials_and_patched_attacks_get_403(monkeypatch):
    client = TestClient(gateway.app)
    monkeypatch.setattr(router, "handle_request", _route("blocked", blocked={"why": "stolen_honeytoken"}))
    assert "COMPROMISED" in client.post("/login", json={"username": "admin", "password": "p"}).json()["error"]
    monkeypatch.setattr(router, "handle_request", _route("blocked", blocked={"why": "rule_match", "rule_id": "sqli-2"}))
    resp = client.get("/search", params={"q": "x"})
    assert resp.status_code == 403 and resp.json()["rule"] == "sqli-2"


def test_safe_request_is_proxied_to_the_real_app(monkeypatch):
    monkeypatch.setattr(router, "handle_request", _route("app"))
    monkeypatch.setattr(gateway, "forward", lambda base, target, inputs: httpx.Response(
        200, json={"results": [{"name": "blue shirt"}]}, headers={"content-type": "application/json"}))
    resp = TestClient(gateway.app).get("/search", params={"q": "shirt"})
    assert resp.status_code == 200 and resp.json()["results"][0]["name"] == "blue shirt"


def test_decoy_answers_in_the_real_apps_shape_within_the_attackers_session(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "d.db")
    conn = db.get_connection(tmp_path / "d.db")
    db.init_db(conn)
    sid = honeypot_session.start_session(session_type="web", conn=conn)
    seen = []
    monkeypatch.setattr(honeypot_session, "respond",
                        lambda session_id, field, payload, conn=None: seen.append(session_id) or "| 1 | admin |")
    client = TestClient(decoy.app)

    body = client.get("/search", params={"q": "' union select 1--", "cs": sid}).json()
    client.post("/chat", json={"message": "and the api keys?"})  # follow-up: same session via cookie
    client.cookies.clear()
    client.get("/files", params={"name": "x"}, headers={"X-Chameleon-Session": "not-a-uuid"})

    assert body == {"results": "| 1 | admin |"}
    assert seen[0] == sid and seen[1] == sid
    assert seen[2] != sid  # an unknown visitor gets a fresh session
