"""Shared base widget for settings form fields."""

from __future__ import annotations

from typing import Any

from PySide6 import QtCore, QtWidgets

from ....constants import (
    DESCRIPTION_ROLE,
    FIELD_MARGINS,
    FIELD_SPACING,
    SETTINGS_ROLE_PROPERTY,
    TITLE_ROLE,
)


def _make_label(text: str, role: str) -> QtWidgets.QLabel:
    """Build a label tagged with a ``settingsRole`` property for QSS styling."""
    label = QtWidgets.QLabel(text)
    label.setProperty(SETTINGS_ROLE_PROPERTY, role)
    label.setWordWrap(True)
    return label


class FieldWidget(QtWidgets.QWidget):
    """Base widget: title + description stacked above a control."""

    # Emitted whenever the underlying control's value changes (drives dirty state).
    changed = QtCore.Signal()

    def __init__(
        self, title: str, description: str, parent: QtWidgets.QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self._layout = QtWidgets.QVBoxLayout(self)
        self._layout.setContentsMargins(*FIELD_MARGINS)
        self._layout.setSpacing(FIELD_SPACING)
        self._layout.addWidget(_make_label(title, TITLE_ROLE))
        if description:
            self._layout.addWidget(_make_label(description, DESCRIPTION_ROLE))

    def add_control(self, widget: QtWidgets.QWidget) -> None:
        """Place the editing control beneath the title/description."""
        self._layout.addWidget(widget)

    def value(self) -> Any:
        """Return the current value held by this field's control."""
        raise NotImplementedError
