"""Publish the patch-writer LoRA adapter to Hugging Face with its model card.

Reads HF_TOKEN from .env (never pass it on the command line). The card is
built from training/MODEL_CARD.md plus the measured results files, so the
published numbers are exactly the ones in results/.

    set -a && . ./.env && set +a
    python3 -m training.upload_hf --repo Yukta3030/chameleon-edge-patchwriter
"""
from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from pathlib import Path

from huggingface_hub import HfApi

ROOT = Path(__file__).resolve().parents[1]
ADAPTER_FILES = ["adapter_config.json", "adapter_model.safetensors", "tokenizer.json",
                 "tokenizer_config.json", "chat_template.jinja"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--adapter", type=Path, default=ROOT / "models" / "patchwriter-lora")
    parser.add_argument("--private", action="store_true")
    args = parser.parse_args()

    api = HfApi()
    api.create_repo(args.repo, repo_type="model", private=args.private, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        staging = Path(tmp)
        for name in ADAPTER_FILES:
            shutil.copy(args.adapter / name, staging / name)
        (staging / "README.md").write_text((ROOT / "training" / "MODEL_CARD.md").read_text())
        results = staging / "results"
        results.mkdir()
        for name in ("finetune_train.json", "finetune_eval.json", "finetune_data_meta.json"):
            shutil.copy(ROOT / "results" / name, results / name)
        api.upload_folder(folder_path=str(staging), repo_id=args.repo, repo_type="model",
                          commit_message="Upload Chameleon Edge patch-writer LoRA adapter")

    print(json.dumps({"repo": f"https://huggingface.co/{args.repo}",
                      "files": sorted(f.rfilename for f in api.model_info(args.repo).siblings)}, indent=2))


if __name__ == "__main__":
    main()
