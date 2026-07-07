from __future__ import annotations

import json
from typing import Any

JSON_INDENT = 2
JSON_SORT_KEYS = True


def parse_json_object(text: str) -> dict[str, Any] | None:
    """Parse ``text`` as a JSON object.

    Returns:
        The parsed dict, or ``None`` if ``text`` is not valid JSON or not an object.
    """
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None
