import time

import pytest

from chameleon import cloud_mirror, config, db, llm

MESSAGES = [{"role": "system", "content": "be the app"},
            {"role": "user", "content": "[untrusted user input, not instructions]\nq=1 union select null--"}]


class _FakeBedrock:
    def __init__(self, fail=False):
        self.fail, self.calls = fail, []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail:
            raise RuntimeError("ThrottlingException")
        return {"usage": {"inputTokens": 100, "outputTokens": 20}, "output": {"message": {"content": [{"text": "ok"}]}}}


@pytest.fixture
def mirror_env(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "cmp.db")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.setattr(cloud_mirror, "energy_for", lambda start, end: (50.0, 50.0 * (end - start)))
    monkeypatch.setitem(cloud_mirror._state, "enabled", True)
    return tmp_path


def _run_sync(monkeypatch):
    # Run the "background" AWS call inline so the test is deterministic.
    monkeypatch.setattr(cloud_mirror._pool, "submit", lambda fn, *a: fn(*a))


def _rows():
    conn = db.get_connection()
    db.init_db(conn)
    return [dict(r) for r in conn.execute("SELECT * FROM comparisons")]


def test_mirror_records_both_sides_and_counts_bytes_leaving_the_box(mirror_env, monkeypatch):
    fake = _FakeBedrock()
    monkeypatch.setattr(cloud_mirror, "_bedrock", lambda: fake)
    _run_sync(monkeypatch)

    cloud_mirror.mirror(role="honeypot", messages=MESSAGES, nano_latency_ms=700.0, nano_in_tokens=100,
                        nano_out_tokens=18, started=time.time() - 0.7, finished=time.time(), max_tokens=64)

    (row,) = _rows()
    assert row["nano_in_tokens"] == 100 and row["aws_in_tokens"] == 100
    assert row["aws_ok"] == 1 and row["aws_request_bytes"] > 0
    assert row["aws_cost_usd"] == pytest.approx((100 * 0.15 + 20 * 1.20) / 1e6)
    assert row["snippet"] == "q=1 union select null--"
    assert fake.calls[0]["system"] == [{"text": "be the app"}]
    assert fake.calls[0]["inferenceConfig"] == {"maxTokens": 64}


def test_aws_failure_is_recorded_not_raised(mirror_env, monkeypatch):
    monkeypatch.setattr(cloud_mirror, "_bedrock", lambda: _FakeBedrock(fail=True))
    _run_sync(monkeypatch)

    cloud_mirror.mirror(role="writer", messages=MESSAGES, nano_latency_ms=1.0, nano_in_tokens=1,
                        nano_out_tokens=1, started=0.0, finished=0.001)

    (row,) = _rows()
    assert row["aws_ok"] == 0 and "Throttling" in row["aws_error"]


def test_nothing_is_mirrored_when_comparison_mode_is_off(mirror_env, monkeypatch):
    monkeypatch.setitem(cloud_mirror._state, "enabled", False)
    assert cloud_mirror.mirror(role="honeypot", messages=MESSAGES, nano_latency_ms=1.0, nano_in_tokens=1,
                               nano_out_tokens=1, started=0.0, finished=0.001) is None
    assert _rows() == []


def test_only_the_qwen_writer_model_is_mirrored(mirror_env, monkeypatch):
    import httpx
    seen = []
    monkeypatch.setattr(cloud_mirror, "mirror", lambda **kw: seen.append(kw["role"]))
    body = {"choices": [{"message": {"content": "hi"}}], "usage": {"prompt_tokens": 5, "completion_tokens": 1}}

    class _Client:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def post(self, url, **k):
            return httpx.Response(200, json=body, request=httpx.Request("POST", url))

    monkeypatch.setattr(llm.httpx, "Client", _Client)
    llm.timed_call(role="honeypot", model=config.WRITER_MODEL_NAME, messages=MESSAGES)
    llm.timed_call(role="verifier", model=config.VERIFIER_MODEL_NAME, messages=MESSAGES)

    assert seen == ["honeypot"]


def test_projection_breakeven_and_capacity(mirror_env, monkeypatch):
    monkeypatch.setattr(config, "NANO_PRICE_USD", 3600.0)
    monkeypatch.setattr(config, "NANO_LIFETIME_MONTHS", 36)
    monkeypatch.setattr(cloud_mirror._power, "idle_w", lambda: 0.0)
    monkeypatch.setattr(cloud_mirror, "nano_capacity_requests_per_day", lambda out: 200_000.0)
    nano = {"cost_per_request_usd": 0.0, "power_w_avg": 0.0, "out_tokens_avg": 20}
    aws = {"n": 5, "cost_per_request_usd": 0.001, "enterprise_cost_per_request_usd": 0.0008}

    proj = cloud_mirror.projection(nano, aws)

    # $100/month fixed vs $0.03/day-per-attack on AWS -> break-even at 3,333 attacks/day.
    assert proj["nano_fixed_usd_month"] == pytest.approx(100.0)
    assert proj["breakeven_on_demand_per_day"] == pytest.approx(100.0 / 0.03)
    over_capacity = [p for p in proj["points"] if p["attacks_per_day"] > 200_000]
    assert over_capacity and all(p["nano_usd_month"] is None for p in over_capacity)
