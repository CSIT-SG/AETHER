import json
from pathlib import Path
from typing import Any

from aether_gui.utils.ui import StyledComponent
from PySide6 import QtCore, QtWidgets


class JsonEditor(StyledComponent):
    """Raw JSON view of the settings.

    A monospace editor seeded from the form's values via :meth:`set_values`.
    Owns the JSON concerns: serializing values in and parsing the edited text
    back out (:meth:`parse`). Emits :attr:`changed` on every edit.
    """

    changed = QtCore.Signal()

    def setup(self) -> None:
        self._editor: QtWidgets.QPlainTextEdit

    def init_ui(self) -> None:
        editor = QtWidgets.QPlainTextEdit(self)
        editor.setObjectName("SettingsJson")
        editor.textChanged.connect(self.changed)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(editor)
        self._editor = editor
        self.setLayout(layout)

    def style_file(self) -> Path | None:
        return Path(__file__).with_name("styles.qss.jinja")

    def set_values(self, data: dict[str, Any]) -> None:
        """Show ``data`` as pretty-printed JSON."""
        self._editor.setPlainText(json.dumps(data, indent=2))

    def text(self) -> str:
        """Return the editor's raw text."""
        return self._editor.toPlainText()

    def parse(self) -> dict[str, Any] | None:
        """Parse the edited text, returning a dict or ``None`` if invalid."""
        try:
            parsed = json.loads(self.text())
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
