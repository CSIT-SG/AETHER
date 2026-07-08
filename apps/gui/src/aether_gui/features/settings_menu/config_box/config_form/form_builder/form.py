from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypedDict

from PySide6 import QtWidgets

from ..fields import FieldWidget

# Collects the live control values into a nested dict mirroring the model.
type Getter = Callable[[], dict[str, Any]]


@dataclass
class SearchMeta:
    """Search/index metadata for one editable settings field."""

    search_text: str
    widget: FieldWidget
    category: str


class Section(TypedDict):
    """A titled section in display order; drives the sidebar."""

    title: str
    widget: QtWidgets.QWidget


class FilterResult(TypedDict):
    """Outcome of applying a search filter to the form."""

    visible: int
    total: int
    # Categories with at least one visible field, or None when no filter is active.
    categories: set[str] | None


@dataclass
class SettingsForm:
    """Everything the settings panel needs to render, navigate and search."""

    widget: QtWidgets.QWidget
    getter: Getter
    sections: list[Section] = field(default_factory=list)
    rows: list[SearchMeta] = field(default_factory=list)

    def has_required_missing(self) -> bool:
        """Whether any required field is currently empty."""
        return any(row.widget.is_required_missing() for row in self.rows)
