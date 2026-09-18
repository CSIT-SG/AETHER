import ida_kernwin
from aether_gui.utils.constants import WINDOW_PREFIX
from aether_utils.logger import get_logger

from .font_action_handlers import (
    FontSizeDecreaseHandler,
    FontSizeIncreaseHandler,
    FontSizeResetHandler,
    SetFontHandler,
)
from .font_action_item import FontActionItem

logger = get_logger("font_hook")


class AetherFontHook(ida_kernwin.UI_Hooks):
    """Detects IDA font actions on the AETHER windows and calls custom actions that then call set_font on
    FontManager to pick up."""

    def __init__(self) -> None:
        super().__init__()

        self.custom_font_actions: list[FontActionItem] = [
            FontActionItem(WINDOW_PREFIX + "_" + "SetFont", SetFontHandler()),
            FontActionItem(WINDOW_PREFIX + "_" + "FontSizeIncrease", FontSizeIncreaseHandler()),
            FontActionItem(WINDOW_PREFIX + "_" + "FontSizeDecrease", FontSizeDecreaseHandler()),
            FontActionItem(WINDOW_PREFIX + "_" + "FontSizeReset", FontSizeResetHandler()),
        ]

    def hook(self) -> bool:
        for item in self.custom_font_actions:
            try:
                item.register()
            except Exception as e:
                logger.error("Failed to register font action %s: %s", item.action_name, e)

        return super().hook()

    def unhook(self):
        for item in self.custom_font_actions:
            try:
                item.unregister()
            except Exception as e:
                logger.warning("Failed to unregister font action %s: %s", item.action_name, e)
        self.custom_font_actions.clear()
        return super().unhook()

    def preprocess_action(self, name: str) -> int:
        target = WINDOW_PREFIX + "_" + name
        if not any(item.action_name == target for item in self.custom_font_actions):
            return 0

        cur = ida_kernwin.get_current_widget()
        if cur is None or not ida_kernwin.get_widget_title(cur).startswith(WINDOW_PREFIX):
            return 0

        ida_kernwin.process_ui_action(target)
        return 1
