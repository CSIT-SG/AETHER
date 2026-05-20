from typing import Any, Literal

import ida_kernwin
import idaapi
from aether_gui.features.chatbot.ui.main_window import MainWindow
from aether_utils.logger import get_logger

class ChatbotHandler(ida_kernwin.action_handler_t):
    def __init__(self) -> None:
        ida_kernwin.action_handler_t.__init__(self)
        self.panel_title = "AETHER ChatBot"
        self.logger = get_logger("chatbot_handler")

    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> Literal[0]:
        curr_form = idaapi.get_current_widget()
        target_title = idaapi.get_widget_title(curr_form)
        target_widget = ida_kernwin.find_widget(target_title)

        if not target_widget:
            self.logger.error(f"Error: Cleanly attach failed. Make sure '{target_title}' is open.")
            return 0

        panel = MainWindow()

        panel.Show(
            self.panel_title,
            options=ida_kernwin.PluginForm.WOPN_DP_RIGHT | ida_kernwin.PluginForm.WOPN_RESTORE
        )

        new_widget = ida_kernwin.find_widget(self.panel_title)

        if new_widget and target_widget:
            # Arguments: (SourceWidget, DestinationWidget, DockPosition)
            ida_kernwin.set_dock_pos(
                self.panel_title,
                target_title,
                ida_kernwin.DP_RIGHT
            )

        return 0

    def update(self, ctx: ida_kernwin.action_ctx_base_t) -> Any:
        return int(ida_kernwin.AST_ENABLE_ALWAYS)
