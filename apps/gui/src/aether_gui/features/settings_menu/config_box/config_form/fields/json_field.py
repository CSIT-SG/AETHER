from __future__ import annotations

import json
from typing import Any

from aether_gui.utils.json import JSON_INDENT
from PySide6 import QtWidgets

from .base import FieldWidget


class JsonField(FieldWidget):
    """Multi-line JSON mini-editor for free-form ``dict`` (or unrecognized) fields.

    ``value()`` parses the text with :func:`json.loads`. It is polled on every
    keystroke by the form's dirty-tracking, so it must never raise: malformed /
    in-progress JSON is returned as the raw string instead. That text flows through
    ``get_content()`` and is rejected by pydantic validation on Apply, surfacing the
    existing error message rather than crashing the UI.
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
        text = "" if value is None else json.dumps(value, indent=JSON_INDENT)
        self._edit.setPlainText(text)
        self._edit.textChanged.connect(self.changed)
        self.add_control(self._edit)

    def value(self) -> Any:
        raw = self._edit.toPlainText().strip()
        if raw == "":
            return None if self._optional else {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # Mid-edit / malformed JSON: hand back the raw text instead of raising.
            # dirty-tracking polls value() on every keystroke, so a raise here would
            # escape a Qt signal handler and crash the dialog. pydantic rejects the
            # string on Apply, so invalid input still surfaces the error message.
            return raw
