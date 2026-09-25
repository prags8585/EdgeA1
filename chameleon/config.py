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


def _load_dotenv(path: Path) -> None:
    """Read KEY=VALUE lines from .env without overriding the real environment.
    Every service (dashboard, scripts) sees the same settings without having to
    be launched with the file sourced first."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv(ROOT / ".env")

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
JEV_API_URL = os.getenv("JEV_API_URL", "") or "https://api.typesafe.ai/v1/systemone"
JEV_MODEL = os.getenv("JEV_MODEL", "jev-latest")
# Jev sits in front of every request, so a slow answer counts as no answer:
# past this budget the Nano check model decides alone.
JEV_TIMEOUT_S = float(os.getenv("JEV_TIMEOUT_S", "2.0"))
JEV_THRESHOLD = float(os.getenv("JEV_THRESHOLD", "0.5"))

# Patch store (Redis). Empty = patches live only in SQLite.
REDIS_URL = os.getenv("REDIS_URL", "")

# Decoy app on the Nano: where malicious requests are redirected.
DECOY_APP_URL = os.getenv("DECOY_APP_URL", "http://127.0.0.1:8300")
# Front-door gateway: the address real clients (and attackers) use.
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://127.0.0.1:8000")

# The four demo app files that approved patches are rendered into.
APPS_DIR = Path(os.getenv("APPS_DIR", str(ROOT / "chameleon" / "apps")))

# --- Nano vs AWS comparison (chameleon.cloud_mirror) ---
# Same model on both sides: Qwen3-Next-80B-A3B. Bedrock on-demand prices for
# us-west-2 from https://aws.amazon.com/bedrock/pricing/ (checked 2026-09-25).
# AWS lists no Provisioned Throughput for this model, so enterprise pricing is
# modelled as a negotiated discount off on-demand, clearly labelled as such.
AWS_REGION = os.getenv("AWS_REGION", "us-west-2")
BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "qwen.qwen3-next-80b-a3b")
BEDROCK_PRICE_IN_PER_1M = float(os.getenv("BEDROCK_PRICE_IN_PER_1M", "0.15"))
BEDROCK_PRICE_OUT_PER_1M = float(os.getenv("BEDROCK_PRICE_OUT_PER_1M", "1.20"))
ENTERPRISE_DISCOUNT = float(os.getenv("ENTERPRISE_DISCOUNT", "0.20"))
COMPARE_WITH_AWS = os.getenv("COMPARE_WITH_AWS", "false").lower() == "true"
# Nano cost inputs. The ZGX Nano's price isn't published on HP's store; the
# default is the $3,999 launch price of NVIDIA's DGX Spark (same GB10 chip) as
# a labelled stand-in -- set NANO_PRICE_USD to the real figure if known.
NANO_PRICE_USD = float(os.getenv("NANO_PRICE_USD", "3999"))
NANO_PRICE_SOURCE = os.getenv("NANO_PRICE_SOURCE", "stand-in: NVIDIA DGX Spark launch price (same GB10 chip)")
NANO_LIFETIME_MONTHS = int(os.getenv("NANO_LIFETIME_MONTHS", "36"))
# California average commercial rate, EIA Electric Power Monthly, April 2026.
ELECTRICITY_USD_PER_KWH = float(os.getenv("ELECTRICITY_USD_PER_KWH", "0.2575"))


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
