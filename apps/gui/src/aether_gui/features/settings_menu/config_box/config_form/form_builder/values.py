"""Value collection helpers for generated settings forms."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .settings_form import Getter


def make_getter(getters: dict[str, Callable[[], Any]]) -> Getter:
    """Bundle per-field value callables into a single nested-dict getter."""

    def getter() -> dict[str, Any]:
        return {name: get() for name, get in getters.items()}

    return getter
