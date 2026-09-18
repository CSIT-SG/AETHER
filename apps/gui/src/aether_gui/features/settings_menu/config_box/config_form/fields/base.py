from __future__ import annotations

from typing import Any

from aether_gui.features.settings_menu.styles import (
    DESCRIPTION_ROLE,
    REQUIRED_ROLE,
    SETTINGS_ROLE_PROPERTY,
    TITLE_ROLE,
)
from PySide6 import QtCore, QtWidgets


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
        self,
        title: str,
        description: str,
        parent: QtWidgets.QWidget | None = None,
        *,
        required: bool = False,
    ) -> None:
        super().__init__(parent)
        self._layout = QtWidgets.QVBoxLayout(self)
        self._layout.setContentsMargins(0, 6, 0, 6)
        self._layout.setSpacing(4)
        self._layout.addWidget(_make_label(title, TITLE_ROLE))
        if description:
            self._layout.addWidget(_make_label(description, DESCRIPTION_ROLE))
        self._required_label = _make_label("Required", REQUIRED_ROLE) if required else None
        self._required_missing = False
        if self._required_label is not None:
            self._required_label.hide()

    def add_control(self, widget: QtWidgets.QWidget) -> None:
        """Place the editing control beneath the title/description."""
        self._layout.addWidget(widget)
        if self._required_label is not None:
            self._layout.addWidget(self._required_label)

    def _update_required(self, is_empty: bool) -> None:
        """Show the 'Required' hint only while a required field is empty."""
        self._required_missing = self._required_label is not None and is_empty
        if self._required_label is not None:
            self._required_label.setVisible(is_empty)

    def is_required_missing(self) -> bool:
        """Whether this field is required but currently empty."""
        return self._required_missing

    def value(self) -> Any:
        """Return the current value held by this field's control."""
        raise NotImplementedError
