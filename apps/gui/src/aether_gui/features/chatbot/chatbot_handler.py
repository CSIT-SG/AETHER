from typing import Any, Literal, cast

import ida_kernwin
import idaapi
from aether_gui.features.chatbot.components import (
    ChatbotPanel,
    ChatHistoryView,
    create_chat_history_view,
    create_chatbot_panel,
)
from aether_utils.logger import get_logger
from PySide6 import QtWidgets

logger = get_logger("chatbot_handler")


class ChatbotPanelForm(ida_kernwin.PluginForm):
    def __init__(self) -> None:
        super().__init__()
        self.parent: QtWidgets.QWidget | None = None
        self.chat_panel: ChatbotPanel | None = None
        self.chat_history: ChatHistoryView | None = None

    def OnCreate(self, form: object) -> None:
        self.parent = cast(QtWidgets.QWidget, ida_kernwin.PluginForm.FormToPyQtWidget(form))
        layout = QtWidgets.QVBoxLayout(self.parent)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.chat_panel= create_chatbot_panel(self.parent)
        layout.addWidget(self.chat_panel)

        # self.chat_history = create_chat_history_view(self.chat_panel)
        # self.chat_panel.set_body(self.chat_history)

        if self.chat_history is not None:
            conversation = [
                ("User", "Hey AETHER, can you help me summarize this function?"),
                ("AETHER", "Sure. Paste the function or describe its inputs and outputs."),
                ("User", "It takes an address, reads bytes, and returns a parsed struct."),
                (
                    "AETHER",
                    "Got it. It reads memory from the given address and decodes it into a struct for easier access.",
                ),
                ("User", "What if the buffer is too short?"),
                (
                    "AETHER",
                    "It should validate length first and return an error or None when the buffer is insufficient.",
                ),
                ("User", "Can you suggest a name for the helper?"),
                ("AETHER", "Maybe `parse_header_at` or `read_header_struct` depending on usage."),
                ("User", "I need a quick test case idea too."),
                (
                    "AETHER",
                    "Create a fake byte array with a known header and assert the parsed fields match expected values.",
                ),
                ("User", "Nice. Any guardrails for invalid pointers?"),
                (
                    "AETHER",
                    "Check for null, verify the address range, and wrap memory reads in a try/except.",
                ),
                ("User", "Hey AETHER, can you help me summarize this function?"),
                ("AETHER", "Sure. Paste the function or describe its inputs and outputs."),
                ("User", "It takes an address, reads bytes, and returns a parsed struct."),
                (
                    "AETHER",
                    "Got it. It reads memory from the given address and decodes it into a struct for easier access.",
                ),
                ("User", "What if the buffer is too short?"),
                (
                    "AETHER",
                    "It should validate length first and return an error or None when the buffer is insufficient.",
                ),
                ("User", "Can you suggest a name for the helper?"),
                ("AETHER", "Maybe `parse_header_at` or `read_header_struct` depending on usage."),
                ("User", "I need a quick test case idea too."),
                (
                    "AETHER",
                    "Create a fake byte array with a known header and assert the parsed fields match expected values.",
                ),
                ("User", "Nice. Any guardrails for invalid pointers?"),
                (
                    "AETHER",
                    "Check for null, verify the address range, and wrap memory reads in a try/except.",
                ),
            ]
            for sender, message in conversation:
                self.chat_history.append_message(sender, message)

    def OnClose(self, form: object) -> None:
        self.chat_history = None
        self.root = None
        self.parent = None


class ChatbotHandler(ida_kernwin.action_handler_t):
    def __init__(self) -> None:
        ida_kernwin.action_handler_t.__init__(self)
        self.panel_title = "AETHER ChatBot"

    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> Literal[0]:
        curr_form = idaapi.get_current_widget()
        target_title = idaapi.get_widget_title(curr_form)
        target_widget = ida_kernwin.find_widget(target_title)

        if not target_widget:
            logger.error(f"Error: Cleanly attach failed. Make sure '{target_title}' is open.")
            return 0

        panel = ChatbotPanelForm()

        panel.Show(
            self.panel_title,
            options=ida_kernwin.PluginForm.WOPN_DP_RIGHT | ida_kernwin.PluginForm.WOPN_RESTORE,
        )

        new_widget = ida_kernwin.find_widget(self.panel_title)

        if new_widget and target_widget:
            # Arguments: (SourceWidget, DestinationWidget, DockPosition)
            ida_kernwin.set_dock_pos(self.panel_title, target_title, ida_kernwin.DP_RIGHT)

        return 0

    def update(self, ctx: ida_kernwin.action_ctx_base_t) -> Any:
        return int(ida_kernwin.AST_ENABLE_ALWAYS)
