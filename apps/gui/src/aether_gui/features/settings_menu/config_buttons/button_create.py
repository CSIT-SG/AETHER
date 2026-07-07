from collections.abc import Callable

from PySide6 import QtWidgets

from .abstract_button import ConfigButton

APPLY_BUTTON_LABEL = "Apply"
OK_BUTTON_LABEL = "Ok"
CANCEL_BUTTON_LABEL = "Cancel"


class ApplyButton(ConfigButton):
    def __init__(
        self,
        on_apply: Callable[[], None],
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__(APPLY_BUTTON_LABEL, parent=parent)
        self._on_apply = on_apply

    def action(self) -> None:
        self._on_apply()


class OkButton(ConfigButton):
    def __init__(
        self,
        on_ok: Callable[[], None],
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__(OK_BUTTON_LABEL, parent=parent)
        self._on_ok = on_ok

    def action(self) -> None:
        self._on_ok()


class CancelButton(ConfigButton):
    def __init__(self, on_close: Callable, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(CANCEL_BUTTON_LABEL, parent=parent)
        self._on_close: Callable = on_close

    def action(self) -> None:
        self._on_close()
