import ida_kernwin
from aether_utils.logger import get_logger

from .font_action_handlers import SetFontHandler
from .font_action_item import FontActionItem

logger = get_logger("font_hook")


class AetherFontHook(ida_kernwin.UI_Hooks):
    """Detects IDA font actions on the chatbot tab and forwards them as a
    Qt setFont() call on the chatbot window, which fires FontChange for
    FontManager to pick up."""

    def __init__(self) -> None:
        super().__init__()

        self.prefix = "AETHER_"
        self.custom_font_actions: list[FontActionItem] = [
            FontActionItem(self.prefix + "SetFont", SetFontHandler()),
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

    def preprocess_action(self, name) -> int:
        target = self.prefix + name
        if not any(item.action_name == target for item in self.custom_font_actions):
            return 0

        cur = ida_kernwin.get_current_widget()
        if cur is None or ida_kernwin.get_widget_title(cur) != "AETHER ChatBot":
            return 0

        ida_kernwin.process_ui_action(target)
        return 1
