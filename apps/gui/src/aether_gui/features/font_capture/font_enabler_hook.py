import ida_kernwin
from aether_gui.utils.constants import WINDOW_PREFIX
from aether_utils.logger import get_logger

logger = get_logger("font_enabler")


class FontEnablerHook(ida_kernwin.UI_Hooks):
    _ACTIONS = ("SetFont", "FontSizeIncrease", "FontSizeDecrease", "FontSizeReset")

    def current_widget_changed(self, widget, prev_widget):
        if widget is None:
            logger.debug("focus changed: widget is none")
            return

        if ida_kernwin.get_widget_title(widget).startswith(WINDOW_PREFIX):
            for a in self._ACTIONS:
                ida_kernwin.update_action_state(a, ida_kernwin.AST_ENABLE_ALWAYS)
