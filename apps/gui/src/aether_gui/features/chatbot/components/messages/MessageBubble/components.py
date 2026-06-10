from pathlib import Path

import sys

from PySide6 import QtCore
from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget
from aether_gui.features.chatbot.components.messages.Messages.components import Message
from aether_gui.utils.ui.plugins.theme_plugin.types import Theme, ThemeColors
from aether_gui.utils.ui.styled_component import StyledComponent

class MessageBubble(StyledComponent):
    """Message Bubbles"""
    def __init__(
            self,
            message: Message,
            parent=None
            ) -> None:
        self._message = message
        super().__init__(parent)

    def setup(self) -> None:
        self._bubble = None
        self._timestamp = None
        self.is_user = None

    def init_ui(self) -> None:
        """Builds bubble widget with custom background theme"""
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)

        # Layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)

        # Label/Bubble
        bubble = QLabel(self._message.content)
        bubble.setWordWrap(True)
        bubble.setObjectName("MessageText")

        self.setMaximumWidth(700)

        # Timestamp Container
        timestamp_container = QWidget(self)
        timestamp_container.setObjectName("TimestampContainer")

        timestamp_layout = QHBoxLayout(timestamp_container)

        # Timestamp
        if sys.platform == "win32":
            formatted_timestamp = self._message.timestamp.strftime("%#I:%M %p")
        else:
            formatted_timestamp = self._message.timestamp.strftime("%-I:%M %p")

        timestamp = QLabel(formatted_timestamp)
        timestamp.setObjectName("Timestamp")

        # Determine User or Aether bubble
        if self._message.role == "User":
            self.setObjectName("UserBubble")
            self.is_user = True

            timestamp_container.setProperty("role", "user")
            # timestamp_layout.addStretch()
            # timestamp_layout.addWidget(timestamp)
        elif self._message.role == "Aether":
            self.setObjectName("AetherBubble")
            self.is_user = False

            timestamp_container.setProperty("role", "aether")
            # timestamp_layout.addWidget(timestamp)
            # timestamp_layout.addStretch()
        else:
            raise ValueError("tf? Message role neither 'User' nor 'Aether'")

        timestamp_layout.addWidget(timestamp)
        # timestamp_layout.addStretch()

        layout.addWidget(bubble)
        layout.addWidget(timestamp_container)

        self._bubble = bubble
        self._timestamp = timestamp

    def style_file(self) -> Path | None:
        """Return the QSS template that paints the panel background."""
        return Path(__file__).resolve().parent / "styles.qss.jinja"
