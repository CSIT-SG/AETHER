from __future__ import annotations

FIELD_TITLE_ACRONYMS = {"url": "URL", "tls": "TLS", "ai": "AI", "api": "API", "id": "ID"}


def format_field_title(name: str) -> str:
    """Turn a snake_case config field name into a human-readable title."""
    return " ".join(FIELD_TITLE_ACRONYMS.get(part, part.capitalize()) for part in name.split("_"))
