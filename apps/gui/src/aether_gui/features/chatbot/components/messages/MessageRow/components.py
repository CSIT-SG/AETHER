from pathlib import Path

from aether_gui.features.chatbot.components.messages.MessageBubble.components import MessageBubble
from aether_gui.features.chatbot.components.messages.Messages.components import Message, MessageRole
from aether_gui.utils.ui.styled_component import StyledComponent
from PySide6.QtWidgets import QApplication, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget


class MessageRow(StyledComponent):
    """Message Card"""
    def __init__(self, message: Message, parent=None):
        self._message = message
        super().__init__(parent)

    def setup(self) -> None:
        self._copy_btn = None

    def init_ui(self) -> None:
        # NEW LAYOUT BUILT IN FOLLOWING FORMAT
        # BODY - MARKDOWN CONTENT (MESSAGEBUBBLE)
        # FOOTER - COPY BUTTON and future implementations

        # Layout
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        message_card_container = QWidget(self)
        card_layout = QVBoxLayout(message_card_container)

        ### HEADER - USER + TIMESTAMP ###
        header_container = QWidget(self)
        header_layout = QHBoxLayout(header_container)

        match self._message.role:
            case MessageRole.USER:
                name_label = QLabel(self._message.role.value)
                time_label = QLabel(self._message.formatted_timestamp)

                header_layout.addStretch()
                header_layout.addWidget(name_label)
                header_layout.addWidget(time_label)

            case MessageRole.AETHER:
                name_label = QLabel(self._message.role.value)
                time_label = QLabel(self._message.formatted_timestamp)

                header_layout.addWidget(name_label)
                header_layout.addWidget(time_label)
                header_layout.addStretch()
            case _:
                name_label = QLabel("Unknown")
                raise Exception("MessageRow: Unknown Role")

        card_layout.addWidget(header_container)
        ### END HEADER ###

        ### BODY - MARKDOWN CONTENT ###
        bubble = MessageBubble(self._message)
        card_layout.addWidget(bubble)
        ### END BODY ###

        ### FOOTER - OTHER WIDGETS (e.g. copy button) ###
        footer_container = QWidget(self)
        footer_layout = QHBoxLayout(footer_container)

        copy_btn = QPushButton("\u2FFB")
        copy_btn.clicked.connect(self._copy_message)

        self._copy_btn = copy_btn

        footer_layout.addStretch()
        footer_layout.addWidget(copy_btn)

        card_layout.addWidget(footer_container)
        ### END FOOTER ###

        match self._message.role:
            case MessageRole.USER:
                main_layout.addStretch()
                main_layout.addWidget(message_card_container)
            case MessageRole.AETHER:
                main_layout.addWidget(message_card_container)
                main_layout.addStretch()
            case _:
                main_layout.addStretch()
                main_layout.addWidget(message_card_container)

    def _copy_message(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self._message.content)

    def style_file(self) -> Path | None:
        return Path(__file__).resolve().parent / "styles.qss.jinja"
