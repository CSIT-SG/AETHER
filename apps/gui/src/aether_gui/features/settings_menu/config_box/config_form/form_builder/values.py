"""Value collection helpers for generated settings forms."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .settings_form import Getter


def make_getter(getters: dict[str, Callable[[], Any]]) -> Getter:
    """Bundle per-field value-readers into one getter for the whole (sub)model.

    ``getters`` maps each field name to a callable returning that field's
    *current* value (a widget's ``value()`` for leaf fields, or a nested getter
    for sub-models). The returned function invokes them all and assembles the
    nested config dict.

    getter of getters read on demand rather than read and hold on to stale memory
    """

    def getter() -> dict[str, Any]:
        return {name: get() for name, get in getters.items()}

    return getter
