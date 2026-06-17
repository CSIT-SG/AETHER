import json
from collections.abc import Callable
from typing import Any

from aether_utils.config import set_config
from PySide6 import QtWidgets

from .abstract_button import ConfigButton


class ApplyButton(ConfigButton):
    def __init__(
        self, get_content: Callable[[], str], parent: QtWidgets.QWidget | None = None
    ) -> None:
        super().__init__("Apply", parent=parent)
        self._get_content = get_content

    def action(self) -> None:
        formatted: dict[str, Any] = json.loads(self._get_content())
        set_config(formatted)


class OkButton(ConfigButton):
    def __init__(
        self,
        get_content: Callable[[], str],
        on_close: Callable,
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__("Ok", parent=parent)
        self._get_content = get_content
        self._on_close = on_close

    def action(self) -> None:
        formatted: dict[str, Any] = json.loads(self._get_content())
        set_config(formatted)
        self._on_close()


class CancelButton(ConfigButton):
    def __init__(self, on_close: Callable, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__("Cancel", parent=parent)
        self._on_close: Callable = on_close

    def action(self) -> None:
        self._on_close()
