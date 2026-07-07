import json
from collections.abc import Callable
from typing import Any

from aether_utils.config import set_config
from aether_utils.logger import get_logger
from PySide6 import QtWidgets

from ..log_names import CONFIG_SAVE_LOGGER
from .abstract_button import ConfigButton

APPLY_BUTTON_LABEL = "Apply"
OK_BUTTON_LABEL = "Ok"
CANCEL_BUTTON_LABEL = "Cancel"

logger = get_logger(CONFIG_SAVE_LOGGER)


class ApplyButton(ConfigButton):
    def __init__(
        self,
        get_content: Callable[[], str],
        on_error: Callable[[], None],
        clear_message_box: Callable[[], None],
        on_success: Callable[[], None],
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__(APPLY_BUTTON_LABEL, parent=parent)
        self._on_error = on_error
        self._clear_message_box = clear_message_box
        self._get_content = get_content
        self._on_success = on_success

    def action(self) -> None:
        self._clear_message_box()
        try:
            formatted: dict[str, Any] = json.loads(self._get_content())
            set_config(formatted)
            self._on_success()
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
        super().__init__(OK_BUTTON_LABEL, parent=parent)
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
        super().__init__(CANCEL_BUTTON_LABEL, parent=parent)
        self._on_close: Callable = on_close

    def action(self) -> None:
        self._on_close()
