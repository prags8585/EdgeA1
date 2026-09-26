"""Local HTTP API for the check model.

Run on the Nano, bound to localhost only:
    uvicorn chameleon.check.serve:app --host 127.0.0.1 --port 8010
"""
from __future__ import annotations

import os
import time
from functools import lru_cache

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .model import CheckModel

app = FastAPI(title="NanoPot check model")


@lru_cache(maxsize=1)
def get_model() -> CheckModel:
    return CheckModel(os.getenv("CHECK_MODEL_PATH", "models/check_model.joblib"),
                      float(os.getenv("CHECK_THRESHOLD", "0.5")))


class CheckRequest(BaseModel):
    # One entry per untrusted field: each URL/form parameter value, or a chat message.
    inputs: list[str] = Field(min_length=1, max_length=100)


@app.get("/health")
def health() -> dict:
    get_model()
    return {"ok": True}


@app.post("/check")
def check(req: CheckRequest) -> dict:
    start = time.perf_counter()
    result = get_model().check(req.inputs)
    result["latency_ms"] = round((time.perf_counter() - start) * 1000, 3)
    return result
