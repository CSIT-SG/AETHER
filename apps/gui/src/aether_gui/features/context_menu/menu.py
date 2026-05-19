import ida_kernwin
from aether_utils.logger import get_logger

from .model import ContextMenuItem

logger = get_logger("context_menu")


class DummyHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        return 0

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class AetherUIHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle, *args, ctx=None, **kwargs):
        if ctx is None and args:
            ctx = args[0]

        if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_PSEUDOCODE:
            return

        menu_path = "aether-next/"
        items = [
            ContextMenuItem("aether:chatbot", "Open AI Chatbot", DummyHandler()),
            ContextMenuItem("aether:whats_new", "What's new", DummyHandler()),
        ]

        for item in items:
            try:
                item.register()
            except Exception as e:
                logger.warning("Failed to register context menu item: %s", e)
            item.attach_to_popup(widget, popup_handle, default_menu_path=menu_path)


_ui_hooks: AetherUIHooks | None = None


def hook() -> None:
    global _ui_hooks
    if _ui_hooks is None:
        _ui_hooks = AetherUIHooks()
        _ui_hooks.hook()


def unhook() -> None:
    global _ui_hooks
    if _ui_hooks is not None:
        try:
            _ui_hooks.unhook()
        except Exception as e:
            logger.warning("Failed to unhook AETHER UI hooks: %s", e)
        finally:
            _ui_hooks = None
