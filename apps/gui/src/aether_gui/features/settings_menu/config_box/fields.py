"""Leaf input widgets for the schema-driven settings form.

Each :class:`FieldWidget` renders a bold title, an optional wrapping description
(taken from the pydantic ``Field(description=...)``) and a type-appropriate
control, then exposes the current control value via :meth:`FieldWidget.value`.
"""

from __future__ import annotations

import json
from typing import Any

from PySide6 import QtCore, QtWidgets


def _make_label(text: str, role: str) -> QtWidgets.QLabel:
    """Build a label tagged with a ``settingsRole`` property for QSS styling."""
    label = QtWidgets.QLabel(text)
    label.setProperty("settingsRole", role)
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
        self._layout.setContentsMargins(0, 6, 0, 6)
        self._layout.setSpacing(4)
        self._layout.addWidget(_make_label(title, "title"))
        if description:
            self._layout.addWidget(_make_label(description, "description"))

    def add_control(self, widget: QtWidgets.QWidget) -> None:
        """Place the editing control beneath the title/description."""
        self._layout.addWidget(widget)

    def value(self) -> Any:
        """Return the current value held by this field's control."""
        raise NotImplementedError


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


class JsonField(FieldWidget):
    """Multi-line JSON mini-editor for free-form ``dict`` (or unrecognized) fields.

    ``value()`` parses the text with :func:`json.loads`; a malformed entry raises,
    which the Apply/Ok button handlers surface as the existing error message.
    """

    def __init__(
        self,
        title: str,
        description: str,
        value: Any,
        *,
        optional: bool,
        placeholder: str = "",
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__(title, description, parent)
        self._optional = optional
        self._edit = QtWidgets.QPlainTextEdit()
        self._edit.setMinimumHeight(60)
        self._edit.setMaximumHeight(160)
        if placeholder:
            self._edit.setPlaceholderText(placeholder)
        self._edit.setPlainText("" if value is None else json.dumps(value, indent=2))
        self._edit.textChanged.connect(self.changed)
        self.add_control(self._edit)

    def value(self) -> Any:
        raw = self._edit.toPlainText().strip()
        if raw == "":
            return None if self._optional else {}
        return json.loads(raw)
