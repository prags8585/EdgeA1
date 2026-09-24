import json
import time
import uuid

from fastapi.testclient import TestClient

from chameleon import config, db
from chameleon.demoapp.main import CANARY_API_KEY, app


def _client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "demo.db")
    return TestClient(app)


def _approve_rule(tmp_path, rule: dict) -> None:
    conn = db.get_connection(tmp_path / "demo.db")
    db.init_db(conn)
    conn.execute(
        "INSERT INTO patches (id, version, status, attack_type, rule_json, writer_model, created_at) "
        "VALUES (?, 1, 'approved', ?, ?, 'test', ?)",
        (str(uuid.uuid4()), rule["attack_type"], json.dumps(rule), time.time()),
    )
    conn.commit()
    conn.close()


def test_search_returns_matching_products(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    resp = client.get("/search", params={"q": "shirt"})
    assert resp.status_code == 200
    assert len(resp.json()["results"]) == 1


def test_files_endpoint_leaks_canary_on_traversal_shaped_request(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    resp = client.get("/files", params={"name": "../../../etc/passwd"})
    assert resp.status_code == 200
    assert CANARY_API_KEY in resp.json()["content"]


def test_files_endpoint_404s_for_unknown_safe_name(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    resp = client.get("/files", params={"name": "nope.txt"})
    assert resp.status_code == 404


def test_approved_rule_blocks_matching_request(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    _approve_rule(tmp_path, {
        "id": "sqli-1", "field": "*", "type": "regex_deny",
        "pattern": r"union\s+select", "description": "sqli", "attack_type": "sqli",
    })

    blocked = client.get("/search", params={"q": "1 union select null--"})
    allowed = client.get("/search", params={"q": "blue shirt"})

    assert blocked.status_code == 403
    assert allowed.status_code == 200


def test_login_checks_credentials(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    ok = client.post("/login", json={"username": "jsmith", "password": "hunter2"})
    bad = client.post("/login", json={"username": "jsmith", "password": "wrong"})
    assert ok.json() == {"ok": True}
    assert bad.json() == {"ok": False}
