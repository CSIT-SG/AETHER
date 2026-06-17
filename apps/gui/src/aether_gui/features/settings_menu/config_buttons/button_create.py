import json
from collections.abc import Callable
from typing import Any

from aether_utils.config import set_config
from PySide6 import QtWidgets

from .abstract_button import ConfigButton


def load_json(raw: Callable) -> dict[str, Any]:
    try:
        formatted: dict[str, Any] = json.loads(raw())
        return formatted
    except Exception as e:
        print("invalid JSON")
        print(e)
        return {" ": " "}

class ApplyButton(ConfigButton):
    def __init__(
        self, get_content: Callable[[], str], parent: QtWidgets.QWidget | None = None
    ) -> None:
        super().__init__("Apply", parent=parent)
        self._get_content = get_content

    def action(self) -> None:
        formatted = load_json(self._get_content)
        try:
            super().reset_colour(self)
            set_config(formatted)
        except Exception as e:
            print(e)
            super().flash_red(self)


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
        formatted = load_json(self._get_content)
        try:
            super().reset_colour(self)
            set_config(formatted)
            self._on_close()
        except Exception as e:
            print(e)
            super().flash_red(self)


class CancelButton(ConfigButton):
    def __init__(self, on_close: Callable, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__("Cancel", parent=parent)
        self._on_close: Callable = on_close

    def action(self) -> None:
        self._on_close()
