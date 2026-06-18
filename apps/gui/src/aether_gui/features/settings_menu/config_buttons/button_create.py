import json
from collections.abc import Callable
from typing import Any

from aether_utils.config import set_config
from aether_utils.logger import get_logger
from PySide6 import QtWidgets

from .abstract_button import ConfigButton

logger = get_logger("json_loader")

def load_json(raw: str) -> dict[str, Any] | None:
    try:
        formatted: dict[str, Any] = json.loads(raw)
        return formatted
    except Exception as e:
        logger.error("invalid JSON")
        raise e

class ApplyButton(ConfigButton):
    def __init__(self,
        get_content: Callable[[], str],
        on_error: Callable[[],None],
        clear_error: Callable[[],None],
        parent: QtWidgets.QWidget | None = None
    ) -> None:
        super().__init__("Apply", parent=parent)
        self._on_error = on_error
        self._clear_error = clear_error
        self._get_content = get_content

    def action(self) -> None:
        self._clear_error()
        try:
            formatted = load_json(self._get_content())
            if formatted is None:
                return
            set_config(formatted)
        except Exception as e:
            self._on_error()
            logger.error(e)


class OkButton(ConfigButton):
    def __init__(
        self,
        get_content: Callable[[], str],
        on_close: Callable,
        on_error: Callable[[],None],
        clear_error: Callable[[],None],
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__("Ok", parent=parent)
        self._get_content = get_content
        self._on_close = on_close
        self._clear_error = clear_error
        self._on_error = on_error

    def action(self) -> None:
        self._clear_error()
        formatted = load_json(self._get_content())
        if formatted is None:
            return
        try:
            formatted = load_json(self._get_content())
            if formatted is None:
                return
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
