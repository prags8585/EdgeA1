"""Generate fine-tuning data for the small patch-writer model, using the big
writer model on the Nano as the teacher.

Each example is (the exact production writer prompt -> a rule JSON). A teacher
rule is only kept if it passes deterministic checks, so the dataset is
verified by tests rather than by any model's opinion:
  - blocks every attack payload it was shown (replay test),
  - blocks none of the benign examples it was shown,
  - blocks <= 1% of a separate benign pool it never saw.
If the first attempt fails, the teacher retries with the same specific
feedback the production pipeline gives; the passing rule is then paired with
the original no-feedback prompt, so the student learns to get it right first
time.

Path traversal and command injection are excluded here entirely: they're the
held-out families training/eval_patchwriter.py measures generalization on.

Run from the repo root with the project venv (not training/.venv), with the
writer model served. DB_PATH keeps these LLM calls out of the demo database:
    DB_PATH=data/training.db python3 -m training.generate_data --n 600
"""
from __future__ import annotations

import argparse
import json
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import pandas as pd

from chameleon import config
from chameleon.patch import tests as patch_tests
from chameleon.patch import writer as patch_writer

ROOT = Path(__file__).resolve().parents[1]

TRAIN_FAMILIES = {
    # family: (sources its benign examples come from, candidate request fields)
    "sqli": (["httpparams"], ["q", "username", "search", "*"]),
    "xss": (["httpparams"], ["q", "comment", "search", "*"]),
    "prompt-injection": (["deepset", "jackhhao"], ["message", "*"]),
    "jailbreak": (["deepset", "jackhhao"], ["message", "*"]),
}
HELDOUT_EVAL_FAMILIES = {"path-traversal", "cmdi"}
MAX_UNSEEN_FPR = 0.01


def load_pools(data_dir: Path) -> tuple[dict, dict]:
    train = pd.read_csv(data_dir / "train.csv", keep_default_na=False)
    attacks = {
        fam: train[train["attack_type"] == fam]["text"].tolist() for fam in TRAIN_FAMILIES
    }
    benign = {
        src: train[(train["label"] == 0) & (train["source"] == src)]["text"].tolist()
        for src in ("httpparams", "deepset", "jackhhao")
    }
    return attacks, benign


def check_rule(rule, shown_attacks, shown_benign, unseen_benign, field) -> tuple[bool, str | None]:
    missed = patch_tests.missed_payloads(rule, shown_attacks, field=field)
    if missed:
        return False, (
            f"The rule did not block {len(missed)} of the {len(shown_attacks)} attack payloads on replay. "
            f"Your pattern was {rule['pattern']!r}. It missed: {', '.join(repr(m) for m in missed[:10])}"
        )
    bypassed = patch_tests.encoding_bypasses(rule, shown_attacks, field=field)
    if bypassed:
        return False, (
            f"Your pattern {rule['pattern']!r} (type {rule['type']!r}) blocks the raw payloads but not "
            f"their URL-encoded forms, e.g. {patch_tests.url_encode_all(bypassed[0])!r}. Use type "
            "\"normalize_then_deny\", which URL-decodes repeatedly and lowercases before matching."
        )
    fp = patch_tests.false_positives(rule, shown_benign + unseen_benign, field=field)
    shown_fp = [t for t in fp if t in set(shown_benign)]
    unseen_fpr = (len(fp) - len(shown_fp)) / max(1, len(unseen_benign))
    if shown_fp or unseen_fpr > MAX_UNSEEN_FPR:
        return False, (
            f"The rule blocked benign traffic; it must not block real users. "
            f"Your pattern was {rule['pattern']!r}. It wrongly blocked: {', '.join(repr(t) for t in fp[:10])}"
        )
    slow = patch_tests.redos_offender(rule)
    if slow is not None:
        return False, (
            f"Your pattern {rule['pattern']!r} took too long on a long input starting {slow[:40]!r} "
            "(catastrophic backtracking). Avoid nested or overlapping quantifiers."
        )
    return True, None


def drop_redos_examples(path: Path) -> tuple[int, int]:
    """Filter an existing JSONL in place (for runs made before the ReDoS check existed)."""
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    safe = [r for r in rows if patch_tests.redos_offender(json.loads(r["completion"])) is None]
    path.write_text("".join(json.dumps(r) + "\n" for r in safe))
    return len(rows), len(safe)


def make_example(i: int, attacks: dict, benign: dict, seed: int, max_attempts: int) -> dict:
    rng = random.Random(seed + i)
    family = rng.choice(sorted(TRAIN_FAMILIES))
    sources, fields = TRAIN_FAMILIES[family]
    field = rng.choice(fields)
    check_field = "q" if field == "*" else field

    pool = attacks[family]
    shown_attacks = rng.sample(pool, rng.randint(4, 8))
    unseen_attacks = [p for p in rng.sample(pool, min(len(pool), 150)) if p not in shown_attacks][:100]

    benign_pool = [t for src in sources for t in benign[src]]
    drawn = rng.sample(benign_pool, 12 + 300)
    shown_benign, unseen_benign = drawn[:12], drawn[12:]

    rule_id = f"{family}-{i}"
    base_messages = patch_writer.build_messages(family, shown_attacks, shown_benign, rule_id, field)

    feedback, rule, attempts = None, None, 0
    for attempts in range(1, max_attempts + 1):
        try:
            rule = patch_writer.write_rule(
                family, shown_attacks, shown_benign, rule_id, feedback=feedback, field=field,
            )
        except Exception as exc:  # bad JSON / bad regex from the teacher: retry
            feedback = f"Your previous output was invalid: {exc}"
            continue
        ok, feedback = check_rule(rule, shown_attacks, shown_benign, unseen_benign, check_field)
        if ok:
            recall = 1 - len(patch_tests.missed_payloads(rule, unseen_attacks, check_field)) / max(1, len(unseen_attacks))
            return {
                "kept": True, "family": family, "field": field, "attempts": attempts,
                "unseen_same_family_recall": round(recall, 4),
                "messages": base_messages, "completion": json.dumps(rule),
            }
    return {"kept": False, "family": family, "field": field, "attempts": attempts, "last_feedback": feedback}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=600, help="teacher attempts (kept examples will be fewer)")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--max-attempts", type=int, default=5)
    parser.add_argument("--seed", type=int, default=20260925)
    parser.add_argument("--data", type=Path, default=ROOT / "data" / "check")
    parser.add_argument("--out", type=Path, default=ROOT / "data" / "generated" / "patchwriter_train.jsonl")
    args = parser.parse_args()

    attacks, benign = load_pools(args.data)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    lock = threading.Lock()
    kept = rejected = 0
    start = time.time()
    with open(args.out, "w") as f, ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(make_example, i, attacks, benign, args.seed, args.max_attempts) for i in range(args.n)]
        for n_done, fut in enumerate(as_completed(futures), 1):
            ex = fut.result()
            with lock:
                if ex.pop("kept"):
                    kept += 1
                    f.write(json.dumps(ex) + "\n")
                    f.flush()
                else:
                    rejected += 1
            if n_done % 25 == 0 or n_done == args.n:
                print(f"{n_done}/{args.n} done, kept {kept}, rejected {rejected}, {time.time() - start:.0f}s", flush=True)

    meta = {
        "teacher_model": config.WRITER_MODEL_NAME, "seed": args.seed, "attempts": args.n,
        "kept": kept, "rejected": rejected, "max_unseen_fpr": MAX_UNSEEN_FPR,
        "train_families": sorted(TRAIN_FAMILIES), "heldout_eval_families": sorted(HELDOUT_EVAL_FAMILIES),
        "seconds": round(time.time() - start, 1),
    }
    args.out.with_suffix(".meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
