import pytest

from chameleon import fusion
from chameleon.jev import client as jev_client


def _stub_nano(malicious: bool, score: float):
    def _check(inputs):
        return {"malicious": malicious, "score": score, "worst_input_index": 0, "latency_ms": 1.0}
    return _check


def test_malicious_when_nano_flags_and_jev_unavailable(monkeypatch):
    monkeypatch.setattr(fusion, "check_nano", _stub_nano(True, 0.9))
    monkeypatch.setattr(jev_client, "check", lambda inputs: (_ for _ in ()).throw(jev_client.JevUnavailable()))

    result = fusion.decide(["' or 1=1--"])

    assert result["decision"] == "malicious"
    assert result["jev_score"] is None
    assert result["reason"] == "nano_only_jev_unavailable"


def test_safe_when_nano_clears_and_jev_unavailable(monkeypatch):
    monkeypatch.setattr(fusion, "check_nano", _stub_nano(False, 0.02))
    monkeypatch.setattr(jev_client, "check", lambda inputs: (_ for _ in ()).throw(jev_client.JevUnavailable()))

    result = fusion.decide(["blue shirt"])

    assert result["decision"] == "safe"


def test_malicious_when_jev_flags_even_if_nano_clears(monkeypatch):
    monkeypatch.setattr(fusion, "check_nano", _stub_nano(False, 0.1))
    monkeypatch.setattr(jev_client, "check", lambda inputs: {"malicious": True, "score": 0.95})

    result = fusion.decide(["../../etc/passwd"])

    assert result["decision"] == "malicious"
    assert result["jev_score"] == 0.95
    assert result["reason"] == "nano_or_jev"


def test_safe_when_both_clear(monkeypatch):
    monkeypatch.setattr(fusion, "check_nano", _stub_nano(False, 0.05))
    monkeypatch.setattr(jev_client, "check", lambda inputs: {"malicious": False, "score": 0.1})

    result = fusion.decide(["madrid"])

    assert result["decision"] == "safe"
