"""Central settings and the localhost-only safety guard.

Every value can be overridden via .env / the environment. Nothing here talks
to a model directly -- chameleon/llm.py does that, and always goes through
assert_local() first unless the caller explicitly marks a call as cloud.
"""
from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]

ALLOWED_LOCAL_HOSTS = {"127.0.0.1", "localhost"}

# ZRT serves every Nano-hosted LLM through one proxy, routed by the "model"
# field in the request body (the --label given at `zrt serve` time), not by
# port. See HANDOFF.md section 5.4 for how we learned this the hard way.
ZRT_PROXY_URL = os.getenv("ZRT_PROXY_URL", "http://127.0.0.1:8080/v1")
WRITER_MODEL_NAME = os.getenv("WRITER_MODEL_NAME", "writer")
VERIFIER_MODEL_NAME = os.getenv("VERIFIER_MODEL_NAME", "verifier")

CHECK_MODEL_URL = os.getenv("CHECK_MODEL_URL", "http://127.0.0.1:8010")
DEMO_APP_URL = os.getenv("DEMO_APP_URL", "http://127.0.0.1:8200")

GATEWAY_HOST = os.getenv("GATEWAY_HOST", "127.0.0.1")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", "8085"))

DB_PATH = Path(os.getenv("DB_PATH", str(ROOT / "data" / "chameleon.db")))

CLOUD_ENABLED = os.getenv("CLOUD_ENABLED", "false").lower() == "true"
CLOUD_PRICE_IN_PER_1K = float(os.getenv("CLOUD_PRICE_IN_PER_1K", "0"))
CLOUD_PRICE_OUT_PER_1K = float(os.getenv("CLOUD_PRICE_OUT_PER_1K", "0"))
CLOUD_DAILY_REQUEST_BUDGET = int(os.getenv("CLOUD_DAILY_REQUEST_BUDGET", "0"))

JEV_API_KEY = os.getenv("JEV_API_KEY", "")
JEV_API_URL = os.getenv("JEV_API_URL", "")


def assert_local(url: str, *, allow_cloud: bool = False) -> None:
    """Refuse any model URL whose host is not localhost.

    The orchestrator is the only caller allowed to pass allow_cloud=True,
    and only for a job it has explicitly decided to place off the Nano.
    """
    if allow_cloud:
        return
    host = urlparse(url).hostname
    if host not in ALLOWED_LOCAL_HOSTS:
        raise ValueError(f"refusing non-local model URL: {url!r} (host={host!r})")
