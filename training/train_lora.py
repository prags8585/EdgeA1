"""LoRA fine-tune of a small Qwen on the Nano, to write patch rules.

Trains on data/generated/patchwriter_train.jsonl (from generate_data.py).
Loss is on the rule JSON only (prompt-completion format), not the prompt.
Writes the adapter to models/patchwriter-lora/ and metrics to
results/finetune_train.json.

Stop the big writer model first (zrt stop --all) -- training needs the memory.
Run with the training venv:
    source training/.venv/bin/activate && python training/train_lora.py
"""
from __future__ import annotations

import argparse
import json
import platform
import random
import time
from pathlib import Path

import torch
from datasets import Dataset
from peft import LoraConfig
from transformers import AutoModelForCausalLM, AutoTokenizer
from trl import SFTConfig, SFTTrainer

ROOT = Path(__file__).resolve().parents[1]
BASE_MODEL = "/opt/hp/zrt/models/hf/Qwen/Qwen2.5-7B-Instruct/main"


def load_rows(path: Path, seed: int, val_frac: float) -> tuple[list[dict], list[dict]]:
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    rows = [
        {"prompt": r["messages"], "completion": [{"role": "assistant", "content": r["completion"]}]}
        for r in rows
    ]
    random.Random(seed).shuffle(rows)
    n_val = max(1, int(len(rows) * val_frac))
    return rows[n_val:], rows[:n_val]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=ROOT / "data" / "generated" / "patchwriter_train.jsonl")
    parser.add_argument("--base-model", default=BASE_MODEL)
    parser.add_argument("--out", type=Path, default=ROOT / "models" / "patchwriter-lora")
    parser.add_argument("--metrics-out", type=Path, default=ROOT / "results" / "finetune_train.json")
    parser.add_argument("--epochs", type=float, default=2)
    parser.add_argument("--lr", type=float, default=2e-4)
    parser.add_argument("--rank", type=int, default=16)
    parser.add_argument("--seed", type=int, default=20260925)
    args = parser.parse_args()

    train_rows, val_rows = load_rows(args.data, args.seed, val_frac=0.1)
    print(f"train {len(train_rows)} / val {len(val_rows)} examples")

    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    model = AutoModelForCausalLM.from_pretrained(args.base_model, dtype=torch.bfloat16)

    peft_config = LoraConfig(
        r=args.rank, lora_alpha=2 * args.rank, lora_dropout=0.05, task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    )
    sft_config = SFTConfig(
        output_dir=str(args.out / "_checkpoints"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=4,
        gradient_accumulation_steps=4,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_steps=2,
        completion_only_loss=True,
        bf16=True,
        gradient_checkpointing=True,
        max_length=2048,
        logging_steps=5,
        eval_strategy="epoch",
        save_strategy="no",
        report_to="none",
        seed=args.seed,
    )
    trainer = SFTTrainer(
        model=model,
        args=sft_config,
        train_dataset=Dataset.from_list(train_rows),
        eval_dataset=Dataset.from_list(val_rows),
        processing_class=tokenizer,
        peft_config=peft_config,
    )

    torch.cuda.reset_peak_memory_stats()
    start = time.perf_counter()
    result = trainer.train()
    train_seconds = time.perf_counter() - start
    eval_metrics = trainer.evaluate()

    args.out.mkdir(parents=True, exist_ok=True)
    trainer.model.save_pretrained(args.out)
    tokenizer.save_pretrained(args.out)

    metrics = {
        "machine": platform.node(),
        "gpu": torch.cuda.get_device_name(0),
        "base_model": "Qwen/Qwen2.5-7B-Instruct",
        "method": f"LoRA r={args.rank} alpha={2 * args.rank}, bf16, all attention+MLP projections",
        "train_examples": len(train_rows),
        "val_examples": len(val_rows),
        "epochs": args.epochs,
        "train_seconds": round(train_seconds, 1),
        "peak_gpu_memory_gib": round(torch.cuda.max_memory_allocated() / 2**30, 2),
        "final_train_loss": round(result.training_loss, 4),
        "val_loss": round(eval_metrics["eval_loss"], 4),
        "loss_history": [
            {k: round(v, 4) if isinstance(v, float) else v for k, v in e.items() if k in ("step", "loss", "eval_loss")}
            for e in trainer.state.log_history if "loss" in e or "eval_loss" in e
        ],
    }
    args.metrics_out.parent.mkdir(parents=True, exist_ok=True)
    args.metrics_out.write_text(json.dumps(metrics, indent=2) + "\n")
    print(json.dumps({k: v for k, v in metrics.items() if k != "loss_history"}, indent=2))
    print(f"\nadapter -> {args.out}\nmetrics -> {args.metrics_out}")


if __name__ == "__main__":
    main()
