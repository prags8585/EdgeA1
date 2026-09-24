import json
import time
import uuid

from chameleon import db, fusion
from chameleon.jev import client as jev_client


def _stub_nano(malicious: bool, score: float):
    def _check(inputs):
        return {"malicious": malicious, "score": score, "worst_input_index": 0, "latency_ms": 1.0}
    return _check


def _conn(tmp_path):
    conn = db.get_connection(tmp_path / "fusion.db")
    db.init_db(conn)
    return conn


def _approve_rule(conn, rule: dict) -> None:
    conn.execute(
        "INSERT INTO patches (id, version, status, attack_type, rule_json, writer_model, created_at) "
        "VALUES (?, 1, 'approved', ?, ?, 'test', ?)",
        (str(uuid.uuid4()), rule["attack_type"], json.dumps(rule), time.time()),
    )
    conn.commit()


def test_malicious_when_nano_flags_and_jev_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(fusion, "check_nano", _stub_nano(True, 0.9))
    monkeypatch.setattr(jev_client, "check", lambda inputs: (_ for _ in ()).throw(jev_client.JevUnavailable()))

    result = fusion.decide({"q": "' or 1=1--"}, conn=_conn(tmp_path))

    assert result["decision"] == "malicious"
    assert result["jev_score"] is None
    assert result["reason"] == "nano_only_jev_unavailable"


def test_safe_when_nano_clears_and_jev_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(fusion, "check_nano", _stub_nano(False, 0.02))
    monkeypatch.setattr(jev_client, "check", lambda inputs: (_ for _ in ()).throw(jev_client.JevUnavailable()))

    result = fusion.decide({"q": "blue shirt"}, conn=_conn(tmp_path))

    assert result["decision"] == "safe"


def test_malicious_when_jev_flags_even_if_nano_clears(tmp_path, monkeypatch):
    monkeypatch.setattr(fusion, "check_nano", _stub_nano(False, 0.1))
    monkeypatch.setattr(jev_client, "check", lambda inputs: {"malicious": True, "score": 0.95})

    result = fusion.decide({"name": "../../etc/passwd"}, conn=_conn(tmp_path))

    assert result["decision"] == "malicious"
    assert result["jev_score"] == 0.95
    assert result["reason"] == "nano_or_jev"


def test_safe_when_both_clear(tmp_path, monkeypatch):
    monkeypatch.setattr(fusion, "check_nano", _stub_nano(False, 0.05))
    monkeypatch.setattr(jev_client, "check", lambda inputs: {"malicious": False, "score": 0.1})

    result = fusion.decide({"q": "madrid"}, conn=_conn(tmp_path))

    assert result["decision"] == "safe"


def test_malicious_when_approved_rule_matches_even_if_models_clear(tmp_path, monkeypatch):
    monkeypatch.setattr(fusion, "check_nano", _stub_nano(False, 0.05))
    monkeypatch.setattr(jev_client, "check", lambda inputs: (_ for _ in ()).throw(jev_client.JevUnavailable()))
    conn = _conn(tmp_path)
    _approve_rule(conn, {
        "id": "traversal-1", "field": "name", "type": "normalize_then_deny",
        "pattern": r"\.\./", "description": "path traversal", "attack_type": "path-traversal",
    })

    result = fusion.decide({"name": "../../etc/passwd"}, conn=conn)

    assert result["decision"] == "malicious"
    assert result["reason"] == "rule_match"
    assert result["rule_id"] == "traversal-1"
