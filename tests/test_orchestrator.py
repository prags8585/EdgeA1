import json
import subprocess

from chameleon import db, llm
from chameleon.orchestrator import cloud, dispatch, policy


def test_load_policy_has_expected_jobs():
    pol = policy.load_policy()
    assert set(pol["jobs"]) == {"honeypot_turn", "write_patch", "verify_patch"}
    assert pol["jobs"]["verify_patch"]["nano_model"] == "verifier"
    assert pol["cloud_fallback"]["provider"] == "anthropic"


def test_nano_is_ready_true_when_zrt_reports_ready(monkeypatch):
    payload = json.dumps({"processes": [{"label": "writer", "state": "Ready"}]})
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=payload, stderr=""),
    )
    assert dispatch.nano_is_ready("writer") is True


def test_nano_is_ready_false_when_dead_or_missing(monkeypatch):
    payload = json.dumps({"processes": [{"label": "writer", "state": "Dead"}]})
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=payload, stderr=""),
    )
    assert dispatch.nano_is_ready("writer") is False
    assert dispatch.nano_is_ready("verifier") is False


def test_nano_is_ready_false_on_subprocess_error(monkeypatch):
    def _raise(*a, **k):
        raise FileNotFoundError("zrt not found")
    monkeypatch.setattr(subprocess, "run", _raise)
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
