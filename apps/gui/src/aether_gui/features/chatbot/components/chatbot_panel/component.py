from datetime import datetime
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from aether_gui.backend.chatbot import ChatOrchestrator
from aether_gui.utils.chat_session import ChatSession, MessageRole
from aether_gui.utils.mcp import MCPClient
from aether_gui.utils.ui import StyledComponent
from PySide6 import QtCore, QtWidgets

from ..chat_input import ChatInput
from ..messages.MessageArea import MessageArea


class ChatbotPanel(StyledComponent):  # type: ignore[misc]
    """Container that owns the chat layout and background styling."""

    def __init__(self, session: ChatSession, mcp_client: MCPClient, parent: Any = None) -> None:
        self._session = session
        self.mcp_client = mcp_client
        super().__init__(parent)

    def setup(self) -> None:
        self._layout_container: QtWidgets.QVBoxLayout | None = None
        self._message_area: MessageArea | None = None
        self._chat_input: ChatInput | None = None
        self.chat_orchestrator: ChatOrchestrator

    def init_ui(self) -> None:
        """Builds the panel with chat input field and enable themed background painting."""
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)

        # Chat Panel Layout
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        message_area = MessageArea(self._session, parent=self)

        layout.addWidget(message_area)

        chat_input = ChatInput(self)
        chat_input.submitted.connect(self._on_message_submitted)
        layout.addWidget(chat_input)

        layout.setStretchFactor(message_area, 1)

        self._layout_container = layout
        self._message_area = message_area
        self._chat_input = chat_input
        self.chat_orchestrator = ChatOrchestrator(
            self._message_area,
            self.mcp_client,
            self._session,
            on_turn_started=lambda: chat_input.submit_enabled(False),
            on_turn_finished=lambda: chat_input.submit_enabled(True),
        )

        self._message_area.load_message_history()

    def _on_message_submitted(self, user_input: str) -> None:
        """Display User Entered Message on MessageArea Widget"""
        message_area = cast(MessageArea, self._message_area)
        message_area.add_new_message_column(
            message=user_input, id=str(uuid4()), timestamp=datetime.now(), role=MessageRole.USER
        )

        # Backend message handling logic goes here
        self.chat_orchestrator.submit_user_prompt(user_input)

    # TODO:
    # ADD LOADING FEATURE WHILE LLM IS PROCESSING

    def style_file(self) -> Path | None:
        """Return the QSS template that paints the panel background."""
        return Path(__file__).resolve().parent / "styles.qss.jinja"

    def shutdown(self) -> None:
        self.chat_orchestrator.shutdown()


def create_chatbot_panel(
    session: ChatSession, mcp_client: MCPClient, parent: QtWidgets.QWidget | None = None
) -> ChatbotPanel:
    return ChatbotPanel(session, mcp_client, parent)
