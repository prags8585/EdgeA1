"""Mirror Nano LLM calls to the same model on AWS Bedrock, for measurement only.

Both sides run Qwen3-Next-80B-A3B: NVFP4 on the Nano, Bedrock on-demand on AWS.
The Nano's answer is always the one the system uses; the AWS call runs in a
background thread afterwards, so the demo's latency and behaviour don't change.
Each request pair lands in the `comparisons` table.

While comparison mode is on, attack data really does leave the building --
aws_request_bytes counts it, and the dashboard shows it. Off = pure edge.

One asymmetry, stated rather than hidden: the Nano writer uses JSON-schema
constrained decoding, which Bedrock's Converse API doesn't offer, so the AWS
side answers the identical prompt unconstrained. Token counts for the input
side are identical; output lengths can differ slightly.
"""
from __future__ import annotations

import collections
import json
import os
import statistics
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import config, db

_state = {"enabled": config.COMPARE_WITH_AWS}
_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="aws-mirror")
_client = None
_client_lock = threading.Lock()


def configured() -> bool:
    return bool(os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY"))


def enabled() -> bool:
    return _state["enabled"] and configured()


def set_enabled(on: bool) -> None:
    _state["enabled"] = bool(on)
    if on:
        _power.ensure_started()  # so the first mirrored request already has power readings


# ---------------- Nano power ----------------

class _PowerSampler:
    """Samples GPU power (nvidia-smi) once a second in the background, so a
    request's energy can be computed from the power drawn while it ran."""

    def __init__(self) -> None:
        self.samples: collections.deque[tuple[float, float]] = collections.deque(maxlen=900)
        self._started = False
        self._lock = threading.Lock()

    def ensure_started(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
        threading.Thread(target=self._loop, daemon=True, name="power-sampler").start()

    def _loop(self) -> None:
        while True:
            watts = read_gpu_power_w()
            if watts is not None:
                self.samples.append((time.time(), watts))
            time.sleep(1.0)

    def window(self, start: float, end: float) -> list[float]:
        return [w for t, w in list(self.samples) if start - 1.0 <= t <= end + 1.0]

    def idle_w(self) -> float | None:
        values = [w for _, w in list(self.samples)]
        return min(values) if values else None


def read_gpu_power_w() -> float | None:
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=power.draw", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=5,
        )
        return float(out.stdout.strip().splitlines()[0])
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        return None


_power = _PowerSampler()


def energy_for(start: float, end: float) -> tuple[float | None, float | None]:
    """(average watts, joules) drawn while a request ran."""
    _power.ensure_started()
    window = _power.window(start, end) or ([_power.samples[-1][1]] if _power.samples else [])
    if not window:
        return None, None
    avg_w = statistics.mean(window)
    return avg_w, avg_w * max(end - start, 0.0)


# ---------------- AWS side ----------------

def _bedrock():
    global _client
    with _client_lock:
        if _client is None:
            import boto3
            from botocore.config import Config

            _client = boto3.client("bedrock-runtime", region_name=config.AWS_REGION,
                                   config=Config(read_timeout=120, retries={"max_attempts": 2}))
        return _client


def to_converse(messages: list[dict[str, str]]) -> dict:
    system = [{"text": m["content"]} for m in messages if m["role"] == "system"]
    convo = [{"role": m["role"], "content": [{"text": m["content"]}]} for m in messages if m["role"] != "system"]
    return {"system": system, "messages": convo}


def aws_cost_usd(in_tokens: int, out_tokens: int) -> float:
    return (in_tokens * config.BEDROCK_PRICE_IN_PER_1M + out_tokens * config.BEDROCK_PRICE_OUT_PER_1M) / 1e6


def _snippet(messages: list[dict[str, str]]) -> str:
    user = [m["content"] for m in messages if m["role"] == "user"]
    if not user:
        return ""
    lines = [ln for ln in user[-1].splitlines() if ln.strip() and not ln.startswith("[untrusted")]
    return " ".join(lines)[:120]


def mirror(
    *,
    role: str,
    messages: list[dict[str, str]],
    nano_latency_ms: float,
    nano_in_tokens: int,
    nano_out_tokens: int,
    started: float,
    finished: float,
    max_tokens: int | None = None,
    temperature: float | None = None,
) -> str | None:
    """Record the Nano side now and replay the identical prompt on Bedrock in the
    background. Returns the comparison row id, or None when mirroring is off."""
    if not enabled():
        return None
    avg_w, joules = energy_for(started, finished)
    row_id = str(uuid.uuid4())
    conn = db.get_connection()
    try:
        db.init_db(conn)
        conn.execute(
            """INSERT INTO comparisons (id, ts, role, snippet, nano_latency_ms, nano_in_tokens,
                   nano_out_tokens, nano_power_w, nano_energy_j, aws_model, aws_region)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (row_id, time.time(), role, _snippet(messages), nano_latency_ms, nano_in_tokens,
             nano_out_tokens, avg_w, joules, config.BEDROCK_MODEL_ID, config.AWS_REGION),
        )
        conn.commit()
    finally:
        conn.close()
    _pool.submit(_run_aws, row_id, config.DB_PATH, messages, max_tokens, temperature)
    return row_id


def _run_aws(row_id: str, db_path: Path, messages, max_tokens, temperature) -> None:
    body = to_converse(messages)
    request_bytes = len(json.dumps(body).encode())
    inference = {}
    if max_tokens:
        inference["maxTokens"] = int(max_tokens)
    if temperature is not None:
        inference["temperature"] = float(temperature)
    start = time.perf_counter()
    fields: dict = {"aws_request_bytes": request_bytes}
    try:
        resp = _bedrock().converse(modelId=config.BEDROCK_MODEL_ID, inferenceConfig=inference, **body)
        usage = resp["usage"]
        fields.update(aws_latency_ms=(time.perf_counter() - start) * 1000, aws_in_tokens=usage["inputTokens"],
                      aws_out_tokens=usage["outputTokens"], aws_ok=1,
                      aws_cost_usd=aws_cost_usd(usage["inputTokens"], usage["outputTokens"]))
    except Exception as exc:  # noqa: BLE001 - recorded on the row; must never reach the product path
        fields.update(aws_latency_ms=(time.perf_counter() - start) * 1000, aws_ok=0,
                      aws_error=f"{type(exc).__name__}: {str(exc)[:300]}")
    conn = db.get_connection(db_path)
    try:
        sets = ", ".join(f"{k} = ?" for k in fields)
        conn.execute(f"UPDATE comparisons SET {sets} WHERE id = ?", (*fields.values(), row_id))
        conn.commit()
    finally:
        conn.close()


# ---------------- summary for the dashboard ----------------

VOLUMES = [100, 1_000, 10_000, 50_000, 100_000, 500_000, 1_000_000, 5_000_000]


def _pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(q * (len(ordered) - 1))))]


def _mean(values: list[float]) -> float | None:
    return statistics.mean(values) if values else None


def nano_capacity_requests_per_day(out_tokens_per_request: float | None) -> float | None:
    """From the measured writer throughput at 8 concurrent (results/llm_baseline.csv)."""
    path = config.ROOT / "results" / "llm_baseline.csv"
    if not out_tokens_per_request or not path.exists():
        return None
    import csv

    rows = [r for r in csv.DictReader(path.open()) if r["model"] == "writer"]
    if not rows:
        return None
    best_tok_s = max(float(r["tokens_per_s"]) for r in rows)
    return best_tok_s / out_tokens_per_request * 86_400


def summary(conn) -> dict:
    rows = [dict(r) for r in conn.execute("SELECT * FROM comparisons ORDER BY ts DESC")]
    done = [r for r in rows if r["aws_ok"] == 1]
    pending = sum(1 for r in rows if r["aws_ok"] is None)
    failed = [r for r in rows if r["aws_ok"] == 0]

    kwh = config.ELECTRICITY_USD_PER_KWH
    nano_energy = [r["nano_energy_j"] for r in done if r["nano_energy_j"] is not None]
    nano_cost_per_req = [e / 3.6e6 * kwh for e in nano_energy]
    nano = {
        "n": len(done),
        "latency_p50_ms": _pct([r["nano_latency_ms"] for r in done], 0.5),
        "latency_p95_ms": _pct([r["nano_latency_ms"] for r in done], 0.95),
        "in_tokens_avg": _mean([r["nano_in_tokens"] for r in done]),
        "out_tokens_avg": _mean([r["nano_out_tokens"] for r in done]),
        "power_w_avg": _mean([r["nano_power_w"] for r in done if r["nano_power_w"] is not None]),
        "energy_j_avg": _mean(nano_energy),
        "cost_per_request_usd": _mean(nano_cost_per_req),
        "cost_total_usd": sum(nano_cost_per_req),
        "bytes_sent_off_box": 0,
        "works_offline": True,
    }
    aws = {
        "n": len(done),
        "latency_p50_ms": _pct([r["aws_latency_ms"] for r in done], 0.5),
        "latency_p95_ms": _pct([r["aws_latency_ms"] for r in done], 0.95),
        "in_tokens_avg": _mean([r["aws_in_tokens"] for r in done]),
        "out_tokens_avg": _mean([r["aws_out_tokens"] for r in done]),
        "cost_per_request_usd": _mean([r["aws_cost_usd"] for r in done]),
        "cost_total_usd": sum(r["aws_cost_usd"] for r in done),
        "enterprise_cost_per_request_usd": (
            _mean([r["aws_cost_usd"] for r in done]) * (1 - config.ENTERPRISE_DISCOUNT) if done else None),
        "bytes_sent_off_box": sum(r["aws_request_bytes"] or 0 for r in rows),
        "works_offline": False,
        "failed": len(failed),
        "last_error": failed[0]["aws_error"] if failed else None,
    }
    return {
        "pending": pending,
        "nano": nano,
        "aws": aws,
        "projection": projection(nano, aws),
        "recent": [{**r, "nano_cost_usd": None if r["nano_energy_j"] is None else r["nano_energy_j"] / 3.6e6 * kwh}
                   for r in rows[:30]],
    }


def projection(nano: dict, aws: dict) -> dict | None:
    """Monthly cost vs attacks/day. Measured per-request tokens and energy, priced
    with AWS's published on-demand rates, a labelled enterprise discount, and the
    Nano's amortized price + electricity. None until there's measured data."""
    if not aws["n"] or aws["cost_per_request_usd"] is None:
        return None
    kwh = config.ELECTRICITY_USD_PER_KWH
    idle_w = _power.idle_w() or nano["power_w_avg"] or 0.0
    nano_fixed = config.NANO_PRICE_USD / config.NANO_LIFETIME_MONTHS + idle_w * 24 * 30 / 1000 * kwh
    nano_per_req = nano["cost_per_request_usd"] or 0.0
    aws_per_req = aws["cost_per_request_usd"]
    ent_per_req = aws["enterprise_cost_per_request_usd"]
    capacity = nano_capacity_requests_per_day(nano["out_tokens_avg"])

    def breakeven(per_req: float) -> float | None:
        gap = (per_req - nano_per_req) * 30
        return nano_fixed / gap if gap > 0 else None

    points = []
    for v in VOLUMES:
        within = capacity is None or v <= capacity
        points.append({
            "attacks_per_day": v,
            "nano_usd_month": nano_fixed + v * 30 * nano_per_req if within else None,
            "aws_on_demand_usd_month": v * 30 * aws_per_req,
            "aws_enterprise_usd_month": v * 30 * ent_per_req,
        })
    return {
        "points": points,
        "nano_capacity_per_day": capacity,
        "breakeven_on_demand_per_day": breakeven(aws_per_req),
        "breakeven_enterprise_per_day": breakeven(ent_per_req),
        "nano_fixed_usd_month": nano_fixed,
        "assumptions": {
            "aws_on_demand": f"${config.BEDROCK_PRICE_IN_PER_1M}/1M in, ${config.BEDROCK_PRICE_OUT_PER_1M}/1M out "
                             f"({config.AWS_REGION}, AWS published on-demand price)",
            "aws_enterprise": f"on-demand minus {config.ENTERPRISE_DISCOUNT:.0%} (assumed negotiated discount; "
                              "AWS lists no Provisioned Throughput for this model)",
            "nano_hardware": f"${config.NANO_PRICE_USD:,.0f} over {config.NANO_LIFETIME_MONTHS} months "
                             f"({config.NANO_PRICE_SOURCE})",
            "electricity": f"${kwh}/kWh (California commercial average, EIA, April 2026); "
                           "GPU power as reported by nvidia-smi, whole-box draw is higher",
            "nano_capacity": "measured writer throughput at 8 concurrent requests (results/llm_baseline.csv)",
        },
    }
