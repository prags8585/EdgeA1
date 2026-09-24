"""Download the public datasets for the check model into data/raw/."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

RAW = Path(__file__).resolve().parents[1] / "data" / "raw"

HTTPPARAMS_REPO = "https://github.com/Morzeux/HttpParamsDataset"
HF_DATASETS = {
    "deepset": "deepset/prompt-injections",
    "jackhhao": "jackhhao/jailbreak-classification",
}


def fetch_httpparams() -> None:
    dest = RAW / "httpparams"
    if dest.exists():
        print(f"skip {dest} (already downloaded)")
        return
    subprocess.run(["git", "clone", "--depth", "1", HTTPPARAMS_REPO, str(dest)], check=True)


def fetch_hf(name: str, repo_id: str) -> None:
    from datasets import load_dataset

    dest = RAW / name
    dest.mkdir(parents=True, exist_ok=True)
    for split, part in load_dataset(repo_id).items():
        part.to_csv(str(dest / f"{split}.csv"), index=False)
        print(f"{repo_id} [{split}]: {len(part)} rows -> {dest / f'{split}.csv'}")


def main() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    fetch_httpparams()
    failed = []
    for name, repo_id in HF_DATASETS.items():
        try:
            fetch_hf(name, repo_id)
        except Exception as exc:
            print(f"FAILED {repo_id}: {exc}", file=sys.stderr)
            failed.append(repo_id)
    if failed:
        sys.exit(f"Could not download: {', '.join(failed)}")


if __name__ == "__main__":
    main()
