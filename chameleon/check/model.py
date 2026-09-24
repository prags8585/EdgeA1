from __future__ import annotations

from pathlib import Path

import joblib


class CheckModel:
    def __init__(self, path: str | Path, threshold: float = 0.5):
        self.pipeline = joblib.load(path)
        self.threshold = threshold

    def check(self, inputs: list[str]) -> dict:
        """Score every input of one request; the request is as malicious as its worst input."""
        scores = self.pipeline.predict_proba(inputs)[:, 1]
        worst = int(scores.argmax())
        score = float(scores[worst])
        return {"malicious": score >= self.threshold, "score": round(score, 4), "worst_input_index": worst}
