from datetime import datetime
from pathlib import Path
from typing import cast
from uuid import uuid4

from aether_gui.backend.chatbot import ChatOrchestrator
from aether_gui.utils.mcp import MCPClient
from aether_gui.utils.ui import StyledComponent
from PySide6 import QtCore, QtWidgets

from ..chat_input import ChatInput
from ..chat_session import ChatSession
from ..messages.MessageArea import MessageArea
from ..messages.Messages import Message, MessageRole


class ChatbotPanel(StyledComponent):
    """Container that owns the chat layout and background styling."""

    def __init__(self, session: ChatSession, mcp_client: MCPClient, parent=None):
        self._session = session
        self.mcp_client = mcp_client
        super().__init__(parent)

    def setup(self) -> None:
        self._layout_container: QtWidgets.QVBoxLayout | None = None
        self._message_area: MessageArea | None = None
        self._chat_input: ChatInput | None = None
        self.chat_orchestrator = ChatOrchestrator(self, self.mcp_client)

    def init_ui(self) -> None:
        """Builds the panel with chat input field and enable themed background painting."""
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)

        # Chat Panel Layout
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        message_area = MessageArea(self)

        layout.addWidget(message_area)

        chat_input = ChatInput(self)
        chat_input.submitted.connect(self._on_message_submitted)
        layout.addWidget(chat_input)

        layout.setStretchFactor(message_area, 1)

        self._layout_container = layout
        self._message_area = message_area
        self._chat_input = chat_input

        self.load_message_history()

    def _on_message_submitted(self, user_input: str) -> None:
        """Display User Entered Message on MessageArea Widget"""
        message = Message(
            id=str(uuid4()), role=MessageRole.USER, content=user_input, timestamp=datetime.now()
        )

        message_area = cast(MessageArea, self._message_area)
        message_area.add_new_message_bubble(message)

        self._session.add_message(message)

        # Backend message handling logic goes here
        ### TESTING ###
        self.chat_orchestrator.submit_user_prompt(user_input)
        ### END TESTING ###

    # Backend call this function
    def add_new_message_bubble(self, response: str) -> None:
        """Display Response After LLM Finishes Processing"""
        message = Message(
            id=str(uuid4()), role=MessageRole.AETHER, content=response, timestamp=datetime.now()
        )

        message_area = cast(MessageArea, self._message_area)
        message_area.add_new_message_bubble(message)

        self._session.add_message(message)

    def append_to_last_message(self, response: str) -> None:
        if self._message_area:
            self._message_area.append_to_last_message(response)

    def load_message_history(self) -> None:
        """Loads existing messages onto MessageArea"""
        if not self._session.messages:
            return

        message_area = cast(MessageArea, self._message_area)
        for msg in self._session.messages:
            message_area.add_new_message_bubble(msg)

    # TODO:
    # ADD AUTO SCROLL TO BOTTOM FUNCTION HERE
    # ADD LOADING FEATURE WHILE LLM IS PROCESSING

    def style_file(self) -> Path | None:
        """Return the QSS template that paints the panel background."""
        return Path(__file__).resolve().parent / "styles.qss.jinja"

    def shutdown(self):
        self.chat_orchestrator.shutdown()


def create_chatbot_panel(
    session: ChatSession, mcp_client: MCPClient, parent: QtWidgets.QWidget | None = None
) -> ChatbotPanel:
    return ChatbotPanel(session, mcp_client, parent)
