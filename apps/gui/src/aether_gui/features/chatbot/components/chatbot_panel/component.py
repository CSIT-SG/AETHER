from datetime import datetime
from pathlib import Path

from aether_gui.features.chatbot.components.chat_input.component import ChatInput
from aether_gui.features.chatbot.components.messages.MessageArea.components import MessageArea
from aether_gui.features.chatbot.components.messages.Messages.components import Message
from aether_gui.features.chatbot.components.scrollbar.component import ScrollBar
from aether_gui.utils.ui import StyledComponent
from PySide6 import QtCore, QtWidgets


class ChatbotPanel(StyledComponent):
    """Container that owns the chat layout and background styling."""

    def setup(self) -> None:
        self._layout_container: QtWidgets.QVBoxLayout | None = None
        self._message_area: MessageArea | None = None
        self._chat_input: ChatInput | None = None
        self._scrollbar: ScrollBar | None = None

    def init_ui(self) -> None:
        """Builds the panel with chat input field and enable themed background painting."""
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)

        # Main Layout (Chat Panel + Scrollbar)
        main_layout = QtWidgets.QHBoxLayout(self)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(8)

        # Chat Panel Layout
        chat_container = QtWidgets.QWidget(self)
        chat_layout = QtWidgets.QVBoxLayout(chat_container)
        chat_layout.setContentsMargins(8, 8, 8, 8)
        chat_layout.setSpacing(8)

        message_area = MessageArea(self)

        ### TESTING ###
        message_area.append_message(
                Message(
                    role="Aether",
                    content="wassup nigga, whats the passphrase",
                    timestamp=datetime.now()
                    )
                )

        message_area.append_message(
                Message(
                    role="User",
                    content="cock and balls ngaaaa",
                    timestamp=datetime.now()
                    )
                )

        message_area.append_message(
                Message(
                    role="Aether",
                    content="thats right ma NIGGGGGGAAAAAA. LETS GOOOO",
                    timestamp=datetime.now()
                    )
                )
        ### END TESTING ###

        chat_layout.addWidget(message_area)

        chat_input = ChatInput(self)
        chat_layout.addWidget(chat_input)

        chat_layout.setStretchFactor(message_area, 1)

        self._message_area = message_area
        self._chat_input = chat_input

        main_layout.addWidget(chat_container)

        # Scrollbar
        scrollbar_component = ScrollBar(QtCore.Qt.Orientation.Vertical, self)
        main_layout.addWidget(scrollbar_component)

        main_layout.setStretchFactor(chat_container, 1)
        main_layout.setStretchFactor(scrollbar_component, 0)

        self._scrollbar = scrollbar_component

    # def set_body(self, body: QtWidgets.QWidget) -> None:
    #     """Swap the panel body widget (e.g., a chat history view)."""
    #     if self._layout is None:
    #         return
    #     if self._body is not None:
    #         self._layout.removeWidget(self._body)
    #         self._body.setParent(None)
    #     self._body = body
    #     self._layout.addWidget(body)
    #
    #     # Append chat input
    #     self._layout.addWidget(self._chat_input)
    #
    #     self._layout.setStretchFactor(body, 1)
    #TODO:
    # ADD SEND FUNCTION HERE
    # ADD CLEAR FUNCTION HERE
    # ADD SCROLL TO BOTTOM FUNCTION HERE

    def style_file(self) -> Path | None:
        """Return the QSS template that paints the panel background."""
        return Path(__file__).resolve().parent / "styles.qss.jinja"


def create_chatbot_panel(parent: QtWidgets.QWidget | None = None) -> ChatbotPanel:
    return ChatbotPanel(parent)
