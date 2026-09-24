from pathlib import Path

import joblib
import pandas as pd
from fastapi.testclient import TestClient

from chameleon.check import dataset, serve
from chameleon.check.train import build_pipeline, evaluate

BENIGN = ["john smith", "c/ caridad s/n", "40184", "campello, el", "madrid", "null", "blue shirt", "12 main st"]
SQLI = ["1' or '1'='1", "1 union select null--", "' or 1=1--", "admin'--", "1; drop table users--"]
XSS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"]
TRAVERSAL = ["../../../etc/passwd", "/..//..//{file}"]


def _write_httpparams(raw: Path) -> None:
    rows = ([(t, "norm", "norm") for t in BENIGN] + [(t, "sqli", "anom") for t in SQLI]
            + [(t, "xss", "anom") for t in XSS] + [(t, "path-traversal", "anom") for t in TRAVERSAL])
    df = pd.DataFrame(rows, columns=["payload", "attack_type", "label"])
    (raw / "httpparams").mkdir(parents=True)
    df.to_csv(raw / "httpparams" / "payload_train.csv", index=False)
    # Overlaps train on purpose, plus one unique benign row.
    pd.concat([df.head(3), pd.DataFrame([("sevilla", "norm", "norm")], columns=df.columns)]).to_csv(
        raw / "httpparams" / "payload_test.csv", index=False)


def test_build_holds_out_unseen_attack_types_and_dedupes(tmp_path):
    _write_httpparams(tmp_path)
    splits = dataset.build(tmp_path)

    assert not splits["train"]["attack_type"].isin(dataset.HELDOUT_ATTACK_TYPES).any()
    assert set(splits["heldout"]["text"]) == set(TRAVERSAL)
    assert not set(splits["test"]["text"]) & set(splits["train"]["text"])
    assert set(splits["test"]["text"]) == {"sevilla"}
    assert "null" in set(splits["train"]["text"])
    assert set(splits["train"]["label"]) == {0, 1}


def _toy_train() -> pd.DataFrame:
    rows = [(t, 0) for t in BENIGN] + [(t, 1) for t in SQLI + XSS]
    return pd.DataFrame(rows * 3, columns=["text", "label"])


def test_evaluate_counts():
    train = _toy_train()
    model = build_pipeline().fit(train["text"], train["label"])
    metrics = evaluate(model, train, threshold=0.5)
    assert metrics["tp"] + metrics["fn"] == 3 * len(SQLI + XSS)
    assert metrics["recall"] > 0.9 and metrics["false_positive_rate"] < 0.1


def test_check_endpoint_flags_request_by_worst_input(tmp_path, monkeypatch):
    train = _toy_train()
    model_path = tmp_path / "check.joblib"
    joblib.dump(build_pipeline().fit(train["text"], train["label"]), model_path)
    monkeypatch.setenv("CHECK_MODEL_PATH", str(model_path))
    serve.get_model.cache_clear()
    client = TestClient(serve.app)

    safe = client.post("/check", json={"inputs": ["john smith", "madrid"]}).json()
    attack = client.post("/check", json={"inputs": ["john smith", "' or 1=1--"]}).json()

    assert safe["malicious"] is False
    assert attack["malicious"] is True and attack["worst_input_index"] == 1
    assert client.post("/check", json={"inputs": []}).status_code == 422
