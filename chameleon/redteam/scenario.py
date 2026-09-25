"""Red-team scenario: drives the full demo storyline end to end.

1. Normal traffic passes through untouched.
2. Known attack types (SQLi, prompt injection) get caught by the check
   layer and rerouted to the honeypot.
3. A held-out attack type (path traversal -- never in training, see
   chameleon.check.dataset.HELDOUT_ATTACK_TYPES) slips past the check
   layer, reaches the demo app, and trips a canary.
4. That canary trip feeds the patch pipeline: writer -> tests -> verifier.
5. A second wave of the same attack type is now caught, because the
   approved rule feeds back into the check layer (chameleon.fusion).

Deterministic: every sample is drawn with a fixed seed, so a demo run
reproduces the same story (and the same numbers) every time.
"""
from __future__ import annotations

import random
from pathlib import Path

import pandas as pd

from .. import config, router
from ..patch import pipeline as patch_pipeline

DEFAULT_SEED = 20260925


def _sample(csv_path: Path, attack_type: str, n: int, seed: int) -> list[str]:
    df = pd.read_csv(csv_path, keep_default_na=False)
    pool = df[df["attack_type"] == attack_type]["text"].tolist()
    rng = random.Random(seed)
    return rng.sample(pool, min(n, len(pool)))


def run(
    conn,
    data_dir: Path,
    *,
    n_benign: int = 20,
    n_sqli: int = 10,
    n_prompt_injection: int = 10,
    n_traversal: int = 10,
    seed: int = DEFAULT_SEED,
    on_progress=None,
) -> dict:
    progress = on_progress or (lambda phase: None)
    test_csv = data_dir / "test.csv"
    heldout_csv = data_dir / "heldout.csv"

    benign = _sample(test_csv, "benign", n_benign, seed)
    sqli = _sample(test_csv, "sqli", n_sqli, seed + 1)
    prompt_injection = _sample(test_csv, "prompt-injection", n_prompt_injection, seed + 2)
    traversal_wave_1 = _sample(heldout_csv, "path-traversal", n_traversal, seed + 3)

    events: list[dict] = []

    progress(f"normal traffic ({len(benign)} requests)")
    for text in benign:
        events.append({"phase": "benign", "text": text, **router.handle_request({"q": text}, conn=conn)})
    progress(f"SQL injection ({len(sqli)} requests)")
    for text in sqli:
        events.append({"phase": "sqli", "text": text, **router.handle_request({"q": text}, conn=conn)})
    progress(f"prompt injection ({len(prompt_injection)} requests)")
    for text in prompt_injection:
        events.append({
            "phase": "prompt_injection", "text": text,
            **router.handle_request({"message": text}, conn=conn),
        })

    # Held out of training on purpose: expected to slip through the check
    # layer on this first wave and reach the demo app's simulated weakness.
    leaked_wave_1 = []
    progress(f"wave 1: novel path traversal ({len(traversal_wave_1)} requests)")
    for name in traversal_wave_1:
        result = router.handle_request({"name": name}, conn=conn)
        leaked = result["decision"] == "safe"
        events.append({"phase": "traversal_wave_1", "text": name, "leaked": leaked, **result})
        if leaked:
            leaked_wave_1.append(name)

    wave1_detection_rate = (
        1 - (len(leaked_wave_1) / len(traversal_wave_1)) if traversal_wave_1 else None
    )

    patch_result = None
    if leaked_wave_1:
        benign_for_rule = _sample(test_csv, "benign", 30, seed + 4)
        progress("writing + testing + verifying a patch on the Nano")
        patch_result = patch_pipeline.run(
            conn,
            attack_type="path-traversal",
            attack_payloads=leaked_wave_1,
            benign_examples=benign_for_rule,
            writer_model=config.WRITER_MODEL_NAME,
            field="name",
        )

    traversal_wave_2 = _sample(heldout_csv, "path-traversal", n_traversal, seed + 5)
    leaked_wave_2 = 0
    progress(f"wave 2: same attack type ({len(traversal_wave_2)} requests)")
    for name in traversal_wave_2:
        result = router.handle_request({"name": name}, conn=conn)
        leaked = result["decision"] == "safe"
        events.append({"phase": "traversal_wave_2", "text": name, "leaked": leaked, **result})
        if leaked:
            leaked_wave_2 += 1

    wave2_detection_rate = (
        1 - (leaked_wave_2 / len(traversal_wave_2)) if traversal_wave_2 else None
    )

    return {
        "events": events,
        "wave1_detection_rate": wave1_detection_rate,
        "wave2_detection_rate": wave2_detection_rate,
        "patch_result": patch_result,
    }


def summarize(result: dict, seconds: float) -> dict:
    by_phase: dict[str, dict] = {}
    for e in result["events"]:
        p = by_phase.setdefault(e["phase"], {"n": 0, "rerouted_to_honeypot": 0})
        p["n"] += 1
        p["rerouted_to_honeypot"] += e["routed_to"] == "honeypot"
    patch = result["patch_result"] or {}
    return {
        "seconds": round(seconds, 1),
        "by_phase": by_phase,
        "wave1_detection_rate": result["wave1_detection_rate"],
        "wave2_detection_rate": result["wave2_detection_rate"],
        "patch_status": patch.get("status"),
        "patch_attempts": patch.get("attempts"),
        "patch_rule": patch.get("rule"),
        "sample_honeypot_replies": [
            {"phase": e["phase"], "attack": e["text"][:120], "reply": e["honeypot_reply"]}
            for e in result["events"] if e.get("honeypot_reply")
        ][:6],
    }


def main() -> None:
    import argparse
    import json
    import time

    from .. import db

    parser = argparse.ArgumentParser(description="Run the red-team scenario against the live system.")
    parser.add_argument("--data", type=Path, default=config.ROOT / "data" / "check")
    parser.add_argument("--out", type=Path, default=config.ROOT / "results" / "redteam_scenario.json")
    args = parser.parse_args()

    conn = db.get_connection()
    db.init_db(conn)
    start = time.perf_counter()
    summary = summarize(run(conn, args.data), time.perf_counter() - start)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "sample_honeypot_replies"}, indent=2))
    print(f"-> {args.out}")


if __name__ == "__main__":
    main()
