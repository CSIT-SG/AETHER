from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .settings_form import Getter


def make_getter(getters: dict[str, Callable[[], Any]]) -> Getter:
    """Return reader that collects current values from field readers. Prevents stale data"""
    return lambda: {name: get() for name, get in getters.items()}
