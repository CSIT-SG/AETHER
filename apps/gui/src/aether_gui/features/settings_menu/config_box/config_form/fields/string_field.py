from __future__ import annotations

from typing import Any

from PySide6 import QtCore, QtGui, QtWidgets

from .base import FieldWidget


class ExampleLineEdit(QtWidgets.QLineEdit):
    def __init__(self, example: str = "", parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self._example = example

    def event(self, event: QtCore.QEvent) -> bool:
        if (
            self._example
            and event.type() == QtCore.QEvent.Type.KeyPress
            and isinstance(event, QtGui.QKeyEvent)
            and event.key() == QtCore.Qt.Key.Key_Tab
            and event.modifiers() == QtCore.Qt.KeyboardModifier.NoModifier
            and self.text() == ""
        ):
            self.setText(self._example)
            event.accept()
            return True
        return super().event(event)


class StringField(FieldWidget):
    """Single-line text field. Optional fields map an empty string to ``None``."""

    def __init__(
        self,
        title: str,
        description: str,
        value: Any,
        *,
        optional: bool,
        required: bool = False,
        placeholder: str = "",
        example: str = "",
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__(title, description, parent, required=required)
        self._optional = optional
        self._edit = ExampleLineEdit(example)
        self._edit.setText("" if value is None else str(value))
        if placeholder:
            self._edit.setPlaceholderText(placeholder)
        self._edit.textChanged.connect(self.changed)
        self._edit.textChanged.connect(lambda text: self._update_required(text == ""))
        self.add_control(self._build_control())
        self._update_required(self._edit.text() == "")

    def _build_control(self) -> QtWidgets.QWidget:
        """The control placed beneath the label. Subclasses may wrap the line edit."""
        return self._edit

    def value(self) -> str | None:
        text = self._edit.text()
        if self._optional and text == "":
            return None
        return text
