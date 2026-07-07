"""Text formatting helpers shared by settings menu components."""

from __future__ import annotations

from .constants import FIELD_TITLE_ACRONYMS


def format_field_title(name: str) -> str:
    """Turn a snake_case config field name into a human-readable title."""
    return " ".join(FIELD_TITLE_ACRONYMS.get(part, part.capitalize()) for part in name.split("_"))
