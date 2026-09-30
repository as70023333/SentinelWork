"""Shared test helpers."""
from __future__ import annotations

from pathlib import Path

from soc_agent.config import PROJECT_ROOT, Settings

POLICY_PATH = PROJECT_ROOT / "config" / "ir_policy.yaml"


def demo_settings(**overrides) -> Settings:
    s = Settings(mode="demo", policy_path=POLICY_PATH, db_path=Path(":memory:"),
                 demo_data_dir=PROJECT_ROOT / "demo_data", demo_latency=False)
    for k, v in overrides.items():
        setattr(s, k, v)
    return s
