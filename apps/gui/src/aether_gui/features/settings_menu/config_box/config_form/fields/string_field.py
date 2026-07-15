from __future__ import annotations

from collections.abc import Callable
from typing import Any

from aether_gui.features.settings_menu.styles import FIELD_BUTTON_OBJECT_NAME
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
    """Single-line text field. Optional fields map an empty string to ``None``.

    Secret fields render the value masked with a show/hide toggle to their right;
    subclasses can add further trailing buttons via :meth:`add_trailing_button`.
    """

    _SECRET_SHOW = "Show"
    _SECRET_HIDE = "Hide"

    def __init__(
        self,
        title: str,
        description: str,
        value: Any,
        *,
        optional: bool,
        required: bool = False,
        secret: bool = False,
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

        self._row_layout: QtWidgets.QHBoxLayout | None = None
        if secret:
            self._edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
            self.add_control(self._build_control_row(self._edit))
            self._secret_toggle = self._make_field_button(
                self._SECRET_SHOW, "Show or hide the value", self._toggle_secret, checkable=True
            )
            self._toggle_width_locked = False
            self.add_trailing_button(self._secret_toggle)
        else:
            self.add_control(self._edit)
        self._update_required(self._edit.text() == "")

    def _build_control_row(self, edit: QtWidgets.QWidget) -> QtWidgets.QWidget:
        """Wrap ``edit`` in a horizontal row that trailing buttons can be added to."""
        row = QtWidgets.QWidget(self)
        layout = QtWidgets.QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        layout.addWidget(edit, 1)
        self._row_layout = layout
        return row

    def add_trailing_button(self, button: QtWidgets.QPushButton) -> None:
        """Append a button to the right of the control (only when a row exists)."""
        if self._row_layout is not None:
            self._row_layout.addWidget(button)

    def _make_field_button(
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
        self._secret_toggle.setText(self._SECRET_HIDE if shown else self._SECRET_SHOW)

    def showEvent(self, event: QtGui.QShowEvent) -> None:
        """Reserve the show/hide toggle's width to its wider label so it never reflows."""
        super().showEvent(event)
        toggle = getattr(self, "_secret_toggle", None)
        if toggle is None or self._toggle_width_locked:
            return
        self._toggle_width_locked = True
        current = toggle.text()
        widest = 0
        for label in (self._SECRET_SHOW, self._SECRET_HIDE):
            toggle.setText(label)
            widest = max(widest, toggle.sizeHint().width())
        toggle.setText(current)
        toggle.setMinimumWidth(widest)

    def value(self) -> str | None:
        text = self._edit.text()
        if self._optional and text == "":
            return None
        return text
