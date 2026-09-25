import json
from pathlib import Path
import uuid

from fastapi.testclient import TestClient

from chameleon import config
from chameleon.demoapp.main import CANARY_API_KEY, app


def _client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "demo.db")
    return TestClient(app)


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
    # The rule reaches the app as rendered code: install it into a copy of the apps.
    import importlib
    import shutil
    import sys

    from chameleon.patch import integrate

    pkg = tmp_path / "patched_apps"
    shutil.copytree(Path(__file__).parent.parent / "chameleon" / "apps", pkg,
                    ignore=shutil.ignore_patterns("__pycache__"))
    integrate.sync([{"id": str(uuid.uuid4()), "writer_model": "test", "rule_json": json.dumps({
        "id": "sqli-1", "field": "*", "type": "regex_deny",
        "pattern": r"union\s+select", "description": "sqli", "attack_type": "sqli"})}], apps_dir=pkg)
    monkeypatch.syspath_prepend(str(tmp_path))
    search_app = importlib.import_module("patched_apps.search_app")
    client = TestClient(search_app.app)

    blocked = client.get("/search", params={"q": "1 union select null--"})
    allowed = client.get("/search", params={"q": "blue shirt"})

    assert blocked.status_code == 403 and blocked.json()["detail"]["rule_id"] == "sqli-1"
    assert allowed.status_code == 200
    sys.modules.pop("patched_apps.search_app", None)


def test_login_checks_credentials(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    ok = client.post("/login", json={"username": "jsmith", "password": "hunter2"})
    bad = client.post("/login", json={"username": "jsmith", "password": "wrong"})
    assert ok.json() == {"ok": True}
    assert bad.json() == {"ok": False}
