from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from PySide6 import QtWidgets

from ..fields import FieldWidget

# Collects the live control values into a nested dict mirroring the model.
Getter = Callable[[], dict[str, Any]]


@dataclass
class SearchMeta:
    """Search/index metadata for one editable settings field."""

    search_text: str
    widget: FieldWidget
    category: str


@dataclass
class SettingsForm:
    """Everything the settings panel needs to render, navigate and search."""

    widget: QtWidgets.QWidget
    getter: Getter
    # (category title, section widget) in display order - drives the sidebar.
    sections: list[tuple[str, QtWidgets.QWidget]] = field(default_factory=list)
    rows: list[SearchMeta] = field(default_factory=list)
