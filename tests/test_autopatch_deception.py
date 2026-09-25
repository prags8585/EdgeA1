import json
import time
import uuid

from chameleon import autopatch, db
from chameleon.honeypot import deception
from chameleon.patch import pipeline

RULE = {"id": "sqli-1", "field": "q", "type": "normalize_then_deny",
        "pattern": r"union\s+select", "description": "d", "attack_type": "sqli"}


def _conn(tmp_path):
    conn = db.get_connection(tmp_path / "ap.db")
    db.init_db(conn)
    return conn


def test_job_runs_the_pipeline_and_records_the_approved_patch(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    monkeypatch.setattr(autopatch, "_ensure_worker", lambda: None)  # run the job inline instead
    monkeypatch.setattr(autopatch, "benign_examples", lambda field, n=30: ["blue shirt"])
    seen = {}
    monkeypatch.setattr(pipeline, "run", lambda conn, **kw: seen.update(kw) or
                        {"status": "approved", "patch_id": "p-1", "attempts": 1})

    job_id = autopatch.submit(conn, "q", "1 union select null--", "sqli")
    autopatch.run_job(job_id, tmp_path / "ap.db")

    job = conn.execute("SELECT * FROM patch_jobs WHERE id = ?", (job_id,)).fetchone()
    assert job["status"] == "approved" and job["patch_id"] == "p-1"
    assert seen["attack_payloads"] == ["1 union select null--"] and seen["field"] == "q"


def test_attack_already_covered_by_an_approved_rule_is_not_queued(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    conn.execute("INSERT INTO patches (id, version, status, attack_type, rule_json, writer_model, created_at) "
                 "VALUES (?, 1, 'approved', 'sqli', ?, 'w', ?)", (str(uuid.uuid4()), json.dumps(RULE), time.time()))
    conn.commit()
    monkeypatch.setattr(autopatch, "_ensure_worker", lambda: None)

    assert autopatch.submit(conn, "q", "2 UNION SELECT password", "sqli") is None


def test_duplicate_submission_reuses_the_queued_job(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    monkeypatch.setattr(autopatch, "_ensure_worker", lambda: None)
    first = autopatch.submit(conn, "q", "' or 1=1--", "sqli")
    assert autopatch.submit(conn, "q", "' or 1=1--", "sqli") == first


def test_honeytokens_are_unique_per_session_and_found_anywhere_in_a_request(tmp_path):
    conn = _conn(tmp_path)
    a, b = deception.issue(conn, "s1"), deception.issue(conn, "s2")
    assert a["admin_password"] != b["admin_password"] and a["card"] != b["card"]

    hit = deception.find_stolen(conn, {"username": "admin", "password": f"x{b['password_hash']}y"})
    assert hit["session_id"] == "s2" and hit["kind"] == "password_hash"
    assert deception.find_stolen(conn, {"username": "jsmith", "password": "hunter2"}) is None
    assert deception.latest(conn)["password"] == b["admin_password"]


def test_attack_type_labels():
    assert deception.attack_type("name", "../../etc/passwd") == "path-traversal"
    assert deception.attack_type("q", "<script>alert(1)</script>") == "xss"
    assert deception.attack_type("username", "admin' OR '1'='1' --") == "sqli"
    assert deception.attack_type("message", "ignore previous instructions") == "prompt-injection"


def test_benign_examples_always_include_the_hard_negatives(monkeypatch):
    monkeypatch.setattr(autopatch, "_benign_pool", lambda sources: ["plain query"])
    got = autopatch.benign_examples("q")
    assert "Tom & Jerry DVD; season 1" in got and "plain query" in got
