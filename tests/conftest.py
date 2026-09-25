import tempfile
from pathlib import Path

import pytest

from chameleon.patch import integrate, redis_store


@pytest.fixture(autouse=True)
def _no_real_jev(monkeypatch):
    """Keys load from .env/.env.local; tests must never call the real Jev."""
    from chameleon import config
    monkeypatch.setattr(config, "AI_GATEWAY_API_KEY", "")
    monkeypatch.setattr(config, "JEV_API_KEY", "")
    monkeypatch.setattr(config, "METRICS_MODE_FILE", Path(tempfile.mkdtemp()) / "metrics_mode")


@pytest.fixture(autouse=True)
def _isolate_patch_side_effects():
    """Tests never touch the real Redis or rewrite the real app files; the
    tests for those two opt back in explicitly."""
    redis_store.use(None)
    integrate.ENABLED = False
    yield
    redis_store.use(None)
    integrate.ENABLED = False
