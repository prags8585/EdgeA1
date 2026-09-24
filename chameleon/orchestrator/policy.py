"""Load the placement policy from config/routing.yaml (not hardcoded)."""
from __future__ import annotations

from pathlib import Path

import yaml

from .. import config

DEFAULT_POLICY_PATH = config.ROOT / "config" / "routing.yaml"


def load_policy(path: Path | None = None) -> dict:
    with open(path or DEFAULT_POLICY_PATH) as f:
        return yaml.safe_load(f)
