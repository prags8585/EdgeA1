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
    assert result["reason"] == "jev_only" and result["flagged_by"] == ["jev"]


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


def test_jev_is_asked_first_with_the_named_fields(tmp_path, monkeypatch):
    order = []
    monkeypatch.setattr(fusion, "check_nano", lambda inputs: order.append("nano") or
                        {"malicious": True, "score": 0.9, "worst_input_index": 1})
    monkeypatch.setattr(jev_client, "check", lambda fields: order.append(("jev", fields)) or
                        {"malicious": True, "score": 0.97, "attack_type": "sqli", "latency_ms": 80.0})

    result = fusion.decide({"username": "admin' --", "password": "x"}, conn=_conn(tmp_path))

    assert order == [("jev", {"username": "admin' --", "password": "x"}), "nano"]
    assert result["reason"] == "jev_and_nano" and result["jev_attack_type"] == "sqli"
    assert result["worst_field"] == "password"


def test_jev_parse_handles_noul_and_choice_shapes():
    parsed = jev_client.parse({"model": "jev-1.13", "answers": {
        "is_attack": {"type": "noul", "noul": 0.93},
        "attack_type": {"type": "choice", "probabilities": {"sqli": 0.8, "none": 0.2}}}})
    assert parsed["malicious"] and parsed["score"] == 0.93 and parsed["attack_type"] == "sqli"
    assert jev_client.parse({"answers": {"is_attack": {"probabilities": {"yes": 0.1, "no": 0.9}}}})["malicious"] is False


def test_jev_parse_handles_the_ai_gateway_boolean_shape():
    parsed = jev_client.parse({"answers": {
        "is_attack": {"type": "boolean", "probability": 0.94},
        "attack_type": {"type": "choice", "choice": "command-injection", "probabilities": {"command-injection": 0.9}}}})
    assert parsed["malicious"] and parsed["score"] == 0.94 and parsed["attack_type"] == "command-injection"


def test_jev_goes_through_ai_gateway_and_retries_a_503(monkeypatch):
    import httpx
    from chameleon import config
    monkeypatch.setattr(config, "AI_GATEWAY_API_KEY", "k")
    calls = []

    def _post(url, json=None, headers=None, timeout=None):
        calls.append((url, headers["ai-model-id"], json["questions"]["is_attack"]["type"]))
        if len(calls) == 1:
            return httpx.Response(503, text="busy")
        return httpx.Response(200, json={"answers": {"is_attack": {"type": "boolean", "probability": 0.9},
                                                     "attack_type": {"type": "choice", "choice": "sqli"}}})
    monkeypatch.setattr(jev_client.httpx, "post", _post)

    result = jev_client.check({"q": "1 union select 1"})

    assert len(calls) == 2 and calls[0] == (f"{config.AI_GATEWAY_URL}/evaluation-model", "typesafe-ai/jev", "boolean")
    assert result["malicious"] and result["backend"] == "vercel-ai-gateway"


def test_jev_gives_up_within_its_time_budget(monkeypatch):
    import httpx
    from chameleon import config
    monkeypatch.setattr(config, "AI_GATEWAY_API_KEY", "k")
    monkeypatch.setattr(config, "JEV_TIMEOUT_S", 0.3)
    monkeypatch.setattr(jev_client.httpx, "post", lambda *a, **k: httpx.Response(503, text="busy"))
    import pytest
    with pytest.raises(jev_client.JevUnavailable, match="HTTP 503"):
        jev_client.check({"q": "x"})
