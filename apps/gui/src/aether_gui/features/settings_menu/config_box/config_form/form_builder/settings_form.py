"""Output types produced by the settings form builder."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from PySide6 import QtWidgets

from ....constants import GENERAL_CATEGORY
from ..fields import FieldWidget

# (search text, leaf widget, category title) for every editable field.
Row = tuple[str, FieldWidget, str]

# Collects the live control values into a nested dict mirroring the model.
Getter = Callable[[], dict[str, Any]]


@dataclass
class SettingsForm:
    """Everything the settings panel needs to render, navigate and search."""

    widget: QtWidgets.QWidget
    getter: Getter
    # (category title, section widget) in display order - drives the sidebar.
    sections: list[tuple[str, QtWidgets.QWidget]] = field(default_factory=list)
    rows: list[Row] = field(default_factory=list)
