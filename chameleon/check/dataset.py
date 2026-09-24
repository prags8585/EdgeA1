"""Merge the raw public datasets into one labeled dataset for the check model.

Writes data/check/{train,test,heldout}.csv with columns:
text, label (1 = malicious), source, attack_type.

heldout.csv holds attack types that never appear in training, so we can
show the model catches attacks it has not seen.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
COLUMNS = ["text", "label", "source", "attack_type"]
HELDOUT_ATTACK_TYPES = {"path-traversal"}


def _frame(text: pd.Series, label: pd.Series, source: str, attack_type: pd.Series | str) -> pd.DataFrame:
    df = pd.DataFrame({"text": text.astype(str), "label": label.astype(int).to_numpy()})
    df["source"] = source
    df["attack_type"] = attack_type if isinstance(attack_type, str) else attack_type.to_numpy()
    df.loc[df["label"] == 0, "attack_type"] = "benign"
    return df


def load_httpparams(raw: Path) -> dict[str, pd.DataFrame]:
    out = {}
    for split, fname in (("train", "payload_train.csv"), ("test", "payload_test.csv")):
        df = pd.read_csv(raw / "httpparams" / fname, keep_default_na=False)
        out[split] = _frame(df["payload"], df["label"] == "anom", "httpparams", df["attack_type"])
    return out


def load_deepset(raw: Path) -> dict[str, pd.DataFrame]:
    out = {}
    for split in ("train", "test"):
        df = pd.read_csv(raw / "deepset" / f"{split}.csv", keep_default_na=False)
        out[split] = _frame(df["text"], df["label"], "deepset", "prompt-injection")
    return out


def load_jackhhao(raw: Path) -> dict[str, pd.DataFrame]:
    out = {}
    for split in ("train", "test"):
        df = pd.read_csv(raw / "jackhhao" / f"{split}.csv", keep_default_na=False)
        out[split] = _frame(df["prompt"], df["type"] == "jailbreak", "jackhhao", "jailbreak")
    return out


LOADERS = {"httpparams": load_httpparams, "deepset": load_deepset, "jackhhao": load_jackhhao}


def build(raw: Path) -> dict[str, pd.DataFrame]:
    parts: dict[str, list[pd.DataFrame]] = {"train": [], "test": []}
    for name, loader in LOADERS.items():
        if not (raw / name).exists():
            print(f"WARNING: {raw / name} missing, skipping {name} (run scripts/fetch_datasets.py)")
            continue
        for split, df in loader(raw).items():
            parts[split].append(df)
    if not parts["train"]:
        raise SystemExit(f"No datasets found under {raw}")

    train = pd.concat(parts["train"], ignore_index=True)
    test = pd.concat(parts["test"], ignore_index=True)
    for df in (train, test):
        df.drop(df[df["text"].str.strip() == ""].index, inplace=True)

    held = lambda df: df["attack_type"].isin(HELDOUT_ATTACK_TYPES)
    heldout = pd.concat([train[held(train)], test[held(test)]], ignore_index=True)
    train = train[~held(train)].drop_duplicates("text")
    test = test[~held(test)].drop_duplicates("text")
    # Exact duplicates across splits would inflate test scores.
    test = test[~test["text"].isin(train["text"])]
    heldout = heldout.drop_duplicates("text")
    heldout = heldout[~heldout["text"].isin(train["text"])]

    return {"train": train[COLUMNS], "test": test[COLUMNS], "heldout": heldout[COLUMNS]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw", type=Path, default=ROOT / "data" / "raw")
    parser.add_argument("--out", type=Path, default=ROOT / "data" / "check")
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    for split, df in build(args.raw).items():
        df.to_csv(args.out / f"{split}.csv", index=False)
        print(f"\n{split}: {len(df)} rows -> {args.out / f'{split}.csv'}")
        print(df.groupby(["source", "attack_type"]).size().to_string())


if __name__ == "__main__":
    main()
