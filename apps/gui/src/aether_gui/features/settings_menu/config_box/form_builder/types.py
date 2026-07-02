"""Shared data structures for the settings form builder.

These are the values passed between the introspection stage (which resolves
pydantic fields) and the builder stage (which turns them into Qt widgets).
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel
from pydantic.fields import FieldInfo
from PySide6 import QtWidgets

from ..fields import FieldWidget

# Category for top-level scalar fields that don't belong to a nested model.
GENERAL_CATEGORY = "General"

# (search text, leaf widget, category title) for every editable field.
Row = tuple[str, FieldWidget, str]
# Collects the live control values into a nested dict mirroring the model.
Getter = Callable[[], dict[str, Any]]


@dataclass
class SettingsForm:
    """Everything the settings panel needs to render, navigate and search."""

    widget: QtWidgets.QWidget
    getter: Getter
    # (category title, section widget) in display order — drives the sidebar.
    sections: list[tuple[str, QtWidgets.QWidget]] = field(default_factory=list)
    rows: list[Row] = field(default_factory=list)


@dataclass
class ResolvedField:
    """A single pydantic field resolved into the bits the builder needs."""

    name: str
    info: FieldInfo
    base: Any  # annotation with ``| None`` stripped off
    optional: bool
    value: Any
    title: str
    description: str

    @property
    def is_model(self) -> bool:
        return inspect.isclass(self.base) and issubclass(self.base, BaseModel)
