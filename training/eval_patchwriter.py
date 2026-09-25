"""Base vs fine-tuned patch writer, on attack families the student never trained on.

Serve the base model with the LoRA adapter attached, so one server answers
both (model="base7b" = base, model="patchwriter" = fine-tuned):
    zrt serve hf:Qwen/Qwen2.5-7B-Instruct --label base7b \
      --extra '--enable-lora' --extra '--max-lora-rank=16' \
      --extra '--lora-modules=patchwriter=<repo>/models/patchwriter-lora' \
      --extra '--max-model-len=4096'

Then, from the repo root with the project venv:
    DB_PATH=data/training.db python3 -m training.eval_patchwriter --models base7b patchwriter [writer]

Every model gets the identical production prompt (chameleon.patch.writer.
build_messages) with JSON-schema constrained output, and every rule is
scored by the same deterministic checks the patch pipeline uses.
Writes results/finetune_eval.json.
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd

from chameleon.patch import tests as patch_tests
from chameleon.patch import writer as patch_writer

ROOT = Path(__file__).resolve().parents[1]
MAX_UNSEEN_FPR = 0.01

# Held out of fine-tuning data entirely (see generate_data.HELDOUT_EVAL_FAMILIES).
EVAL_FAMILIES = {
    "path-traversal": ("heldout.csv", ["name", "q", "*"]),
    "cmdi": ("test.csv", ["q", "host", "*"]),
}


def build_tasks(data_dir: Path, per_family: int, seed: int) -> list[dict]:
    test = pd.read_csv(data_dir / "test.csv", keep_default_na=False)
    benign_pool = test[(test["label"] == 0) & (test["source"] == "httpparams")]["text"].tolist()
    tasks = []
    for family, (csv_name, fields) in EVAL_FAMILIES.items():
        df = pd.read_csv(data_dir / csv_name, keep_default_na=False)
        pool = df[df["attack_type"] == family]["text"].tolist()
        for i in range(per_family):
            rng = random.Random(f"{seed}-{family}-{i}")
            shown = rng.sample(pool, min(6, len(pool) - 5))
            drawn = rng.sample(benign_pool, 12 + 300)
            tasks.append({
                "family": family, "i": i, "field": rng.choice(fields),
                "shown_attacks": shown,
                "unseen_attacks": [p for p in pool if p not in shown],
                "shown_benign": drawn[:12], "unseen_benign": drawn[12:],
            })
    return tasks


def score(task: dict, model: str) -> dict:
    field = task["field"]
    check_field = "q" if field == "*" else field
    try:
        rule = patch_writer.write_rule(
            task["family"], task["shown_attacks"], task["shown_benign"],
            rule_id=f"{task['family']}-eval-{task['i']}", field=field, model=model,
        )
    except Exception as exc:
        return {"valid": False, "error": str(exc)[:200]}

    missed_shown = patch_tests.missed_payloads(rule, task["shown_attacks"], check_field)
    missed_unseen = patch_tests.missed_payloads(rule, task["unseen_attacks"], check_field)
    fp_shown = patch_tests.false_positives(rule, task["shown_benign"], check_field)
    fp_unseen = patch_tests.false_positives(rule, task["unseen_benign"], check_field)
    unseen_fpr = len(fp_unseen) / len(task["unseen_benign"])
    replay_pass = not missed_shown
    return {
        "valid": True,
        "replay_pass": replay_pass,
        "shown_benign_clean": not fp_shown,
        "unseen_fpr": unseen_fpr,
        "unseen_recall": 1 - len(missed_unseen) / max(1, len(task["unseen_attacks"])),
        # What the production pipeline would accept (before the verifier).
        "full_pass": replay_pass and not fp_shown and unseen_fpr <= MAX_UNSEEN_FPR,
        "pattern": rule["pattern"],
    }


def summarize(results: list[dict]) -> dict:
    valid = [r for r in results if r["valid"]]
    mean = lambda xs: round(statistics.mean(xs), 4) if xs else None
    return {
        "n": len(results),
        "valid_rate": round(len(valid) / len(results), 4),
        "replay_pass_rate": mean([r["replay_pass"] for r in valid] + [False] * (len(results) - len(valid))),
        "full_pass_rate": mean([r["full_pass"] for r in valid] + [False] * (len(results) - len(valid))),
        "mean_unseen_recall": mean([r["unseen_recall"] for r in valid]),
        "mean_unseen_fpr": mean([r["unseen_fpr"] for r in valid]),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--models", nargs="+", required=True, help="served-as names, e.g. base7b patchwriter writer")
    parser.add_argument("--per-family", type=int, default=40)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--data", type=Path, default=ROOT / "data" / "check")
    parser.add_argument("--out", type=Path, default=ROOT / "results" / "finetune_eval.json")
    args = parser.parse_args()

    tasks = build_tasks(args.data, args.per_family, args.seed)
    report = {"eval_families": sorted(EVAL_FAMILIES), "tasks_per_family": args.per_family,
              "max_unseen_fpr": MAX_UNSEEN_FPR, "models": {}}

    for model in args.models:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            results = list(pool.map(lambda t: score(t, model), tasks))
        by_family = {
            fam: summarize([r for r, t in zip(results, tasks) if t["family"] == fam]) for fam in EVAL_FAMILIES
        }
        report["models"][model] = {"overall": summarize(results), "by_family": by_family}
        print(model, json.dumps(report["models"][model]["overall"]))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"\n-> {args.out}")


if __name__ == "__main__":
    main()
