from collections.abc import Callable

from PySide6 import QtWidgets

from .button_base import ConfigButton


class ApplyButton(ConfigButton):
    def __init__(
        self,
        on_apply: Callable[[], None],
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__("Apply", parent=parent)
        self._on_apply = on_apply

    def action(self) -> None:
        self._on_apply()


class OkButton(ConfigButton):
    def __init__(
        self,
        on_ok: Callable[[], None],
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__("Ok", parent=parent)
        self._on_ok = on_ok

    def action(self) -> None:
        self._on_ok()


class CancelButton(ConfigButton):
    def __init__(self, on_close: Callable, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__("Cancel", parent=parent)
        self._on_close: Callable = on_close

    def action(self) -> None:
        self._on_close()
