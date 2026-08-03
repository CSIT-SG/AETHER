from typing import Any, Literal, cast

import ida_kernwin
import idaapi
from aether_gui.features.chatbot.components import (
    ChatbotPanel,
    create_chatbot_panel,
)
from aether_gui.utils.chat_session import ChatSession
from aether_gui.utils.constants import WINDOW_PREFIX
from aether_gui.utils.mcp import MCPClient
from aether_utils.logger import get_logger
from PySide6 import QtWidgets

logger = get_logger("chatbot_handler")


class ChatbotPanelForm(ida_kernwin.PluginForm):
    def __init__(self, session: ChatSession, mcp_client: MCPClient) -> None:
        super().__init__()
        self._session = session
        self.parent: QtWidgets.QWidget | None = None
        self.chat_panel: ChatbotPanel | None = None
        self.mcp_client = mcp_client

    def OnCreate(self, form: object) -> None:
        self.parent = cast(QtWidgets.QWidget, ida_kernwin.PluginForm.FormToPyQtWidget(form))
        layout = QtWidgets.QVBoxLayout(self.parent)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.chat_panel = create_chatbot_panel(self._session, self.mcp_client, self.parent)
        layout.addWidget(self.chat_panel)

    def OnClose(self, form: object) -> None:
        self.root = None
        self.parent = None
        if self.chat_panel:
            self.chat_panel.shutdown()


class ChatbotHandler(ida_kernwin.action_handler_t):
    def __init__(self, mcp_client: MCPClient) -> None:
        ida_kernwin.action_handler_t.__init__(self)
        self.panel_title = f"{WINDOW_PREFIX} Chatbot"
        self.session = ChatSession()
        self.mcp_client = mcp_client

    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> Literal[0]:
        curr_form = idaapi.get_current_widget()
        target_title = idaapi.get_widget_title(curr_form)
        target_widget = ida_kernwin.find_widget(target_title)

        if not target_widget:
            logger.error(f"Error: Cleanly attach failed. Make sure '{target_title}' is open.")
            return 0

        panel = ChatbotPanelForm(self.session, self.mcp_client)

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
