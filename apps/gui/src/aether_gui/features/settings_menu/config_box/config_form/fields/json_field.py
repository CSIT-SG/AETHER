"""JSON settings field."""

from __future__ import annotations

import json
from typing import Any

from PySide6 import QtWidgets

from ....constants import EMPTY_TEXT, JSON_FIELD_HEIGHT_RANGE, JSON_INDENT
from .base import FieldWidget


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
        self._edit.setMinimumHeight(JSON_FIELD_HEIGHT_RANGE[0])
        self._edit.setMaximumHeight(JSON_FIELD_HEIGHT_RANGE[1])
        if placeholder:
            self._edit.setPlaceholderText(placeholder)
        text = EMPTY_TEXT if value is None else json.dumps(value, indent=JSON_INDENT)
        self._edit.setPlainText(text)
        self._edit.textChanged.connect(self.changed)
        self.add_control(self._edit)

    def value(self) -> Any:
        raw = self._edit.toPlainText().strip()
        if raw == EMPTY_TEXT:
            return None if self._optional else {}
        return json.loads(raw)
