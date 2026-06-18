import json
from collections.abc import Callable
from typing import Any

from aether_utils.config import set_config
from aether_utils.logger import get_logger
from PySide6 import QtWidgets

from .abstract_button import ConfigButton

logger = get_logger("json_loader")


class ApplyButton(ConfigButton):
    def __init__(
        self,
        get_content: Callable[[], str],
        on_error: Callable[[], None],
        clear_message_box: Callable[[], None],
        set_config_message: Callable[[], None],
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__("Apply", parent=parent)
        self._on_error = on_error
        self._clear_message_box = clear_message_box
        self._get_content = get_content
        self._set_config_message = set_config_message

    def action(self) -> None:
        self._clear_message_box()
        try:
            formatted: dict[str, Any] = json.loads(self._get_content())
            set_config(formatted)
            self._set_config_message()
        except Exception as e:
            self._on_error()
            logger.error(e)


class OkButton(ConfigButton):
    def __init__(
        self,
        get_content: Callable[[], str],
        on_close: Callable,
        on_error: Callable[[], None],
        clear_message_box: Callable[[], None],
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__("Ok", parent=parent)
        self._get_content = get_content
        self._on_close = on_close
        self._clear_message_box = clear_message_box
        self._on_error = on_error

    def action(self) -> None:
        self._clear_message_box()
        try:
            formatted: dict[str, Any] = json.loads(self._get_content())
            set_config(formatted)
            self._on_close()
        except Exception as e:
            self._on_error()
            logger.error(e)


class CancelButton(ConfigButton):
    def __init__(self, on_close: Callable, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__("Cancel", parent=parent)
        self._on_close: Callable = on_close

    def action(self) -> None:
        self._on_close()
