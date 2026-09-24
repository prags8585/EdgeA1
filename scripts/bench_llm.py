"""Baseline throughput/latency for a served model, at a few concurrency levels.

Run once both LLMs are up:
    python3 scripts/bench_llm.py --model writer --n 50 --concurrency 1 4 8

Writes results/llm_baseline.csv (appends; one row per (model, concurrency)).
"""
from __future__ import annotations

import argparse
import csv
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]

PROMPT = "In one short sentence, say what a web application firewall does."


def _one_call(base_url: str, model: str, timeout: float) -> dict:
    start = time.perf_counter()
    resp = httpx.post(
        f"{base_url}/chat/completions",
        json={"model": model, "messages": [{"role": "user", "content": PROMPT}], "max_tokens": 64},
        timeout=timeout,
    )
    latency_ms = (time.perf_counter() - start) * 1000
    resp.raise_for_status()
    data = resp.json()
    usage = data.get("usage", {})
    return {"latency_ms": latency_ms, "out_tokens": usage.get("completion_tokens", 0)}


def run(base_url: str, model: str, n: int, concurrency: int, timeout: float) -> dict:
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        start = time.perf_counter()
        results = list(pool.map(lambda _: _one_call(base_url, model, timeout), range(n)))
        wall_s = time.perf_counter() - start

    latencies = sorted(r["latency_ms"] for r in results)
    total_out_tokens = sum(r["out_tokens"] for r in results)
    return {
        "model": model,
        "concurrency": concurrency,
        "n": n,
        "p50_ms": round(latencies[len(latencies) // 2], 1),
        "p95_ms": round(latencies[int(0.95 * (len(latencies) - 1))], 1),
        "wall_s": round(wall_s, 2),
        "requests_per_s": round(n / wall_s, 3),
        "tokens_per_s": round(total_out_tokens / wall_s, 1) if wall_s else 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True, help="served-as name, e.g. writer or verifier")
    parser.add_argument("--base-url", default="http://127.0.0.1:8080/v1")
    parser.add_argument("--n", type=int, default=50)
    parser.add_argument("--concurrency", type=int, nargs="+", default=[1, 4, 8])
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--out", type=Path, default=ROOT / "results" / "llm_baseline.csv")
    args = parser.parse_args()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    write_header = not args.out.exists()

    with open(args.out, "a", newline="") as f:
        fieldnames = ["model", "concurrency", "n", "p50_ms", "p95_ms", "wall_s", "requests_per_s", "tokens_per_s"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        for c in args.concurrency:
            row = run(args.base_url, args.model, args.n, c, args.timeout)
            writer.writerow(row)
            f.flush()
            print(row)

    print(f"\nappended to {args.out}")


if __name__ == "__main__":
    main()
