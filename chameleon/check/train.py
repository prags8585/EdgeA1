"""Train the check model (malicious vs safe) on the Nano and record its metrics."""
from __future__ import annotations

import argparse
import json
import platform
import statistics
import time
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

ROOT = Path(__file__).resolve().parents[2]


def build_pipeline() -> Pipeline:
    # Character n-grams catch payload syntax (quotes, tags, ../); word n-grams catch prompt phrasing.
    features = FeatureUnion([
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=2,
                                 sublinear_tf=True, max_features=300_000)),
        ("word", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=2,
                                 sublinear_tf=True, token_pattern=r"[^\s]+")),
    ])
    clf = LogisticRegression(max_iter=3000, class_weight="balanced", C=4.0)
    return Pipeline([("features", features), ("clf", clf)])


def evaluate(model: Pipeline, df: pd.DataFrame, threshold: float) -> dict:
    pred = (model.predict_proba(df["text"])[:, 1] >= threshold).astype(int)
    y = df["label"].to_numpy()
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "n": len(df),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }


def latency_ms(model: Pipeline, texts: list[str]) -> dict:
    times = []
    for text in texts:
        start = time.perf_counter()
        model.predict_proba([text])
        times.append((time.perf_counter() - start) * 1000)
    times.sort()
    return {"median": round(statistics.median(times), 3),
            "p95": round(times[int(0.95 * (len(times) - 1))], 3)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=ROOT / "data" / "check")
    parser.add_argument("--model-out", type=Path, default=ROOT / "models" / "check_model.joblib")
    parser.add_argument("--metrics-out", type=Path, default=ROOT / "results" / "check_metrics.json")
    parser.add_argument("--threshold", type=float, default=0.5)
    args = parser.parse_args()

    train = pd.read_csv(args.data / "train.csv", keep_default_na=False)
    test = pd.read_csv(args.data / "test.csv", keep_default_na=False)
    heldout = pd.read_csv(args.data / "heldout.csv", keep_default_na=False)

    model = build_pipeline()
    start = time.perf_counter()
    model.fit(train["text"], train["label"])
    train_seconds = time.perf_counter() - start

    metrics = {
        "machine": platform.node(),
        "arch": platform.machine(),
        "train_rows": len(train),
        "train_seconds": round(train_seconds, 2),
        "threshold": args.threshold,
        "test": evaluate(model, test, args.threshold),
        "test_by_source": {src: evaluate(model, df, args.threshold) for src, df in test.groupby("source")},
        # All rows are attacks of types never seen in training, so only recall is meaningful.
        "heldout_recall": evaluate(model, heldout, args.threshold)["recall"] if len(heldout) else None,
        "heldout_types": sorted(heldout["attack_type"].unique().tolist()),
        "latency_ms_per_request": latency_ms(model, test["text"].sample(min(500, len(test)), random_state=0).tolist()),
    }

    args.model_out.parent.mkdir(parents=True, exist_ok=True)
    args.metrics_out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.model_out)
    args.metrics_out.write_text(json.dumps(metrics, indent=2) + "\n")
    print(json.dumps(metrics, indent=2))
    print(f"\nmodel -> {args.model_out}\nmetrics -> {args.metrics_out}")


if __name__ == "__main__":
    main()
