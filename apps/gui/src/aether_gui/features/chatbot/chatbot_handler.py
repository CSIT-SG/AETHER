from typing import Any, Literal, cast

import ida_kernwin
import idaapi
from aether_gui.features.chatbot.components import (
    ChatbotPanel,
    create_chatbot_panel,
)
from aether_gui.features.chatbot.components.chat_session import ChatSession
from aether_utils.logger import get_logger
from PySide6 import QtWidgets

logger = get_logger("chatbot_handler")


class ChatbotPanelForm(ida_kernwin.PluginForm):
    def __init__(self, session: ChatSession) -> None:
        super().__init__()
        self._session = session
        self.parent: QtWidgets.QWidget | None = None
        self.chat_panel: ChatbotPanel | None = None

    def OnCreate(self, form: object) -> None:
        self.parent = cast(QtWidgets.QWidget, ida_kernwin.PluginForm.FormToPyQtWidget(form))
        layout = QtWidgets.QVBoxLayout(self.parent)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.chat_panel = create_chatbot_panel(self._session, self.parent)
        layout.addWidget(self.chat_panel)

    def OnClose(self, form: object) -> None:
        self.root = None
        self.parent = None


class ChatbotHandler(ida_kernwin.action_handler_t):
    def __init__(self, session: ChatSession) -> None:
        ida_kernwin.action_handler_t.__init__(self)
        self.panel_title = "AETHER ChatBot"
        self.session = session

    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> Literal[0]:
        curr_form = idaapi.get_current_widget()
        target_title = idaapi.get_widget_title(curr_form)
        target_widget = ida_kernwin.find_widget(target_title)

        if not target_widget:
            logger.error(f"Error: Cleanly attach failed. Make sure '{target_title}' is open.")
            return 0

        panel = ChatbotPanelForm(self.session)

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
