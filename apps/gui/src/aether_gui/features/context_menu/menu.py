from typing import cast

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

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class AetherUIHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget: object, popup_handle: object, *args: object, ctx: ida_kernwin.action_ctx_base_t | None =None, **kwargs: object) -> None:
        if ctx is None and args:
            ctx = cast(ida_kernwin.action_ctx_base_t, args[0])

        if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_PSEUDOCODE:
            return

        menu_path = "aether-next/"
        items = [
            ContextMenuItem("aether:chatbot", "Open AI Chatbot", ChatbotHandler()),
            ContextMenuItem("aether:whats_new", "What's new", DummyHandler()),
        ]

        for item in items:
            try:
                item.register()
            except Exception as e:
                logger.warning("Failed to register context menu item: %s", e)
            item.attach_to_popup(widget, popup_handle, default_menu_path=menu_path)
