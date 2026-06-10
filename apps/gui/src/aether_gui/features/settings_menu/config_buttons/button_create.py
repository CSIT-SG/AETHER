from collections.abc import Callable

from aether_utils.config import CONFIG_FILE

from .abstract_button import ConfigButton


class ApplyButton(ConfigButton):
    def __init__(self, get_content: Callable) -> None:
        super().__init__("Apply")
        self._get_content: Callable = get_content


    def action(self) -> None:
        self.write_content(CONFIG_FILE, self._get_content())


class OkButton(ConfigButton):
    def __init__(self, get_content: Callable, on_close: Callable) -> None:
        super().__init__("OK")
        self._get_content: Callable = get_content
        self._on_close: Callable = on_close


    def action(self) -> None:
        self.write_content(CONFIG_FILE, self._get_content())
        self._on_close()

class CancelButton(ConfigButton):
    def __init__(self, on_close: Callable) -> None:
        super().__init__("Cancel")
        self._on_close: Callable = on_close


    def action(self) -> None:
        self._on_close()
