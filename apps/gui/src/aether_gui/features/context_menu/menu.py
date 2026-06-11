from typing import cast

from aether_gui.features.chatbot.components.chat_session.component import ChatSession
import ida_kernwin
from aether_gui.features.chatbot import ChatbotHandler
from aether_utils.logger import get_logger

from .menu_item import ContextMenuItem

logger = get_logger("context_menu")


class DummyHandler(ida_kernwin.action_handler_t):
    def __init__(self) -> None:
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx: ida_kernwin.action_ctx_base_t):
        return 0


class AetherUIHooks(ida_kernwin.UI_Hooks):
    def __init__(self) -> None:
        super().__init__()

        self.session = ChatSession()
        self.items = [
            ContextMenuItem("aether:chatbot", "Open AI Chatbot", ChatbotHandler(self.session)),
            ContextMenuItem("aether:whats_new", "What's new", DummyHandler()),
        ]

    def finish_populating_widget_popup(
        self,
        widget: object,
        popup_handle: object,
        *args: object,
        ctx: ida_kernwin.action_ctx_base_t | None = None,
        **kwargs: object,
    ) -> None:

        wtype = ida_kernwin.get_widget_type(widget)
        if ctx is None and args:
            ctx = cast(ida_kernwin.action_ctx_base_t, args[0])

        if wtype != ida_kernwin.BWN_PSEUDOCODE:
            return

        menu_path = "aether-next/"

        for item in self.items:
            try:
                item.register()

            except Exception as e:
                logger.error("Failed to register context menu item: %s", e)

            item.attach_to_popup(widget, popup_handle, default_menu_path=menu_path)

    def unregister(self) -> None:
        for item in self.items:
            try:
                item.unregister()

            except Exception as e:
                logger.warning("Failed to unregister context menu item: %s", e)

        self.items.clear()
