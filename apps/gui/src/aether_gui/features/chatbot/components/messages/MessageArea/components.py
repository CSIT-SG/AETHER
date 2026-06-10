from pathlib import Path

from aether_gui.features.chatbot.components.messages.MessageBubble.components import MessageBubble
from aether_gui.features.chatbot.components.messages.MessageRow.components import MessageRow
from aether_gui.features.chatbot.components.messages.Messages.components import Message
from aether_gui.utils.ui.styled_component import StyledComponent
from PySide6 import QtCore
from PySide6.QtWidgets import QScrollArea, QVBoxLayout, QWidget


class MessageArea(StyledComponent):
    """Literally the message area that contains message bubbles"""

    def setup(self) -> None:
        self._scroll_area = None
        self._messages_container = None
        self._messages_layout = None

    def init_ui(self) -> None:
        """Builds scrollable message area and adds message bubbles"""
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)

        # Layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Scroll Area
        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)

        # Messages layout (for scrollable layout)
        messages_container = QWidget(self)

        messages_layout = QVBoxLayout(messages_container)
        messages_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)

        scroll_area.setWidget(messages_container)
        layout.addWidget(scroll_area)

        self._scroll_area = scroll_area
        self._messages_container = messages_container
        self._messages_layout = messages_layout

        self._messages_layout.addStretch()
        self._messages_layout.setSpacing(12)

    def append_message(self, message:Message):
        bubble = MessageBubble(message)
        row = MessageRow(bubble, bubble.is_user)
        self._messages_layout.addWidget(row)

    def style_file(self) -> Path | None:
        return Path(__file__).resolve().parent / "styles.qss.jinja"

    # def on_theme_change(self, *, theme: Theme, colors: ThemeColors) -> None:
    #     """Re-render cached messages so HTML colors track the new theme."""
    #     if self._text is None:
    #         return
    #     self._text.clear()
    #     for sender, message in self._messages:
    #         rendered = self.render_html(sender=sender, message=message)
    #         if rendered.strip():
    #             self._text.append(rendered)
    #     text_scrollbar = self._text.verticalScrollBar()
    #     text_scrollbar.setValue(text_scrollbar.maximum())

