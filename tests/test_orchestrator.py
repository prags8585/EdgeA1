import httpx

from chameleon import db, llm
from chameleon.orchestrator import cloud, dispatch, policy


def test_load_policy_has_expected_jobs():
    pol = policy.load_policy()
    assert set(pol["jobs"]) == {"honeypot_turn", "write_patch", "verify_patch"}
    assert pol["jobs"]["verify_patch"]["nano_model"] == "verifier"
    assert pol["cloud_fallback"]["provider"] == "anthropic"


def _proxy_lists(monkeypatch, model_ids):
    request = httpx.Request("GET", "http://127.0.0.1:8080/v1/models")
    body = {"data": [{"id": m} for m in model_ids]}
    monkeypatch.setattr(httpx, "get", lambda *a, **k: httpx.Response(200, json=body, request=request))


def test_nano_is_ready_true_when_proxy_routes_the_model(monkeypatch):
    _proxy_lists(monkeypatch, ["writer", "verifier"])
    assert dispatch.nano_is_ready("writer") is True


def test_nano_is_ready_false_when_proxy_does_not_list_it(monkeypatch):
    # The real failure: zrt said "Ready" but the proxy only routed base7b.
    _proxy_lists(monkeypatch, ["base7b", "patchwriter"])
    assert dispatch.nano_is_ready("writer") is False


def test_nano_is_ready_false_when_proxy_down(monkeypatch):
    def _raise(*a, **k):
        raise httpx.ConnectError("connection refused")
    monkeypatch.setattr(httpx, "get", _raise)
    assert dispatch.nano_is_ready("writer") is False


def test_run_job_uses_nano_when_ready(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "timed_call", lambda **kwargs: f"nano reply via {kwargs['model']}")
    conn = db.get_connection(tmp_path / "orch.db")

    reply = dispatch.run_job("write_patch", "sys", "user", conn=conn, nano_ready=True)

    assert reply == "nano reply via writer"


def test_run_job_falls_back_to_cloud_and_logs_it(tmp_path, monkeypatch):
    monkeypatch.setattr(cloud, "chat", lambda provider, system, user, model: {
        "text": "cloud reply", "in_tokens": 10, "out_tokens": 5,
    })
    conn = db.get_connection(tmp_path / "orch.db")
    db.init_db(conn)

    reply = dispatch.run_job("verify_patch", "sys", "user", conn=conn, nano_ready=False)

    assert reply == "cloud reply"
    row = conn.execute("SELECT * FROM llm_calls WHERE role = 'verify_patch'").fetchone()
    assert row["provider"] == "cloud"
    assert row["placement_reason"] == "nano_unreachable"
    assert row["in_tokens"] == 10
