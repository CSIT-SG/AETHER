from __future__ import annotations

from collections.abc import Callable

from aether_gui.features.settings_menu.styles import FIELD_BUTTON_OBJECT_NAME
from PySide6 import QtCore, QtGui, QtWidgets

from .string_field import StringField


class SecretField(StringField):
    """String field whose value is masked, with a show/hide toggle to its right."""

    _SHOW = "Show"
    _HIDE = "Hide"

    def _build_control(self) -> QtWidgets.QWidget:
        """Mask the value and put a show/hide toggle to the right of the line edit."""
        self._edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        row = QtWidgets.QWidget(self)
        self._row_layout = QtWidgets.QHBoxLayout(row)
        self._row_layout.setContentsMargins(0, 0, 0, 0)
        self._row_layout.setSpacing(6)
        self._row_layout.addWidget(self._edit, 1)
        self._toggle = self._make_button(
            self._SHOW, "Show or hide the value", self._toggle_secret, checkable=True
        )
        self._toggle_width_locked = False
        self._row_layout.addWidget(self._toggle)
        return row

    def _make_button(
        self,
        text: str,
        tooltip: str,
        on_click: Callable[..., None],
        *,
        checkable: bool = False,
    ) -> QtWidgets.QPushButton:
        """Build a small themed button matching the settings button styling."""
        button = QtWidgets.QPushButton(text, self)
        button.setObjectName(FIELD_BUTTON_OBJECT_NAME)
        button.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
        button.setToolTip(tooltip)
        button.setCheckable(checkable)
        button.clicked.connect(on_click)
        return button

    def _toggle_secret(self, shown: bool) -> None:
        """Reveal or mask the value and reflect the state in the toggle label."""
        mode = (
            QtWidgets.QLineEdit.EchoMode.Normal if shown else QtWidgets.QLineEdit.EchoMode.Password
        )
        self._edit.setEchoMode(mode)
        self._toggle.setText(self._HIDE if shown else self._SHOW)

    def showEvent(self, event: QtGui.QShowEvent) -> None:
        """Reserve the toggle's width to its wider label so it never reflows."""
        super().showEvent(event)
        if self._toggle_width_locked:
            return
        self._toggle_width_locked = True
        current = self._toggle.text()
        widest = 0
        for label in (self._SHOW, self._HIDE):
            self._toggle.setText(label)
            widest = max(widest, self._toggle.sizeHint().width())
        self._toggle.setText(current)
        self._toggle.setMinimumWidth(widest)
