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
