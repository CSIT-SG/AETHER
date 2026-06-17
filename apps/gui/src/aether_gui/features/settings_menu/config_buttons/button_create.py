from collections.abc import Callable
from typing import Any

from aether_utils.config import get_config, set_config
from PySide6 import QtWidgets

from .abstract_button import ConfigButton

CONFIG_FILE = get_config().model_dump()

class ApplyButton(ConfigButton):
    def __init__(self, get_content: Callable, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__("Apply", parent = parent)
        self._get_content: Callable = get_content


    def action(self) -> None:
        set_config(self._get_content())


class OkButton(ConfigButton):
    def __init__(self, get_content: Callable, on_close: Callable, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__("OK", parent = parent)
        self._get_content: Callable = get_content
        self._on_close: Callable = on_close


    def action(self) -> None:
        set_config(self._get_content())
        self._on_close()

class CancelButton(ConfigButton):
    def __init__(self, on_close: Callable, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__("Cancel", parent = parent)
        self._on_close: Callable = on_close


    def action(self) -> None:
        self._on_close()
