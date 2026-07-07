from __future__ import annotations

from typing import Any

from PySide6 import QtWidgets

from .base import FieldWidget


class BoolField(FieldWidget):
    """Checkbox-backed boolean field."""

    def __init__(
        self,
        title: str,
        description: str,
        value: Any,
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__(title, description, parent)
        self._check = QtWidgets.QCheckBox("Enabled")
        self._check.setChecked(bool(value))
        self._check.toggled.connect(self.changed)
        self.add_control(self._check)

    def value(self) -> bool:
        return self._check.isChecked()
