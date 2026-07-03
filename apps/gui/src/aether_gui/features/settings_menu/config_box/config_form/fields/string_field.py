"""String settings field."""

from __future__ import annotations

from typing import Any

from PySide6 import QtWidgets

from .base import FieldWidget


class StringField(FieldWidget):
    """Single-line text field. Optional fields map an empty string to ``None``."""

    def __init__(
        self,
        title: str,
        description: str,
        value: Any,
        *,
        optional: bool,
        secret: bool = False,
        placeholder: str = "",
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__(title, description, parent)
        self._optional = optional
        self._edit = QtWidgets.QLineEdit("" if value is None else str(value))
        if placeholder:
            self._edit.setPlaceholderText(placeholder)
        if secret:
            self._edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self._edit.textChanged.connect(self.changed)
        self.add_control(self._edit)

    def value(self) -> str | None:
        text = self._edit.text()
        if self._optional and text == "":
            return None
        return text
