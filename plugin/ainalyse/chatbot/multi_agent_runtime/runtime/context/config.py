"""
Context management configuration loader.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any


DEFAULT_CONTEXT_SETTINGS_PATH = Path(__file__).resolve().parents[2] / "context_settings.json"


@lru_cache(maxsize=1)
def load_context_settings() -> dict[str, Any]:
    if not DEFAULT_CONTEXT_SETTINGS_PATH.exists():
        return {}

    payload = json.loads(DEFAULT_CONTEXT_SETTINGS_PATH.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"context_settings.json must contain a JSON object: {DEFAULT_CONTEXT_SETTINGS_PATH}")
    return payload


def get_context_setting(*path: str, default: Any = None) -> Any:
    current: Any = load_context_settings()
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current
