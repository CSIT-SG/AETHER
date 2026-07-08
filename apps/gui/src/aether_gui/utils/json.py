from __future__ import annotations

import json
from typing import Any

JSON_INDENT = 2
JSON_SORT_KEYS = True


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook`` that rejects duplicate keys instead of silently
    keeping the last, which would drop an entry the user typed on purpose."""
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise ValueError(f"duplicate key {key!r}")
        seen.add(key)
    return dict(pairs)


def load_json_object(text: str) -> dict[str, Any]:
    """Parse ``text`` as a JSON object and keep the reason when it is not JSON.
    Uses _reject_duplicate_keys() to reject duplicate json keys
    """
    parsed = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(parsed, dict):
        raise ValueError(f"expected a JSON object, got {type(parsed).__name__}")
    return parsed
