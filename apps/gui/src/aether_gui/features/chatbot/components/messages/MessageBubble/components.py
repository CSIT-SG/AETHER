from pathlib import Path

from markdown import markdown

from PySide6 import QtCore
from PySide6.QtWidgets import QHBoxLayout, QLabel, QTextBrowser, QVBoxLayout, QWidget
from aether_gui.features.chatbot.components.messages.Messages.components import Message, MessageRole
from aether_gui.utils.ui.plugins.theme_plugin.types import Theme, ThemeColors
from aether_gui.utils.ui.styled_component import StyledComponent

class MessageBubble(StyledComponent):
    """Message Bubbles - contain markdown content"""
    def __init__(
            self,
            message: Message,
            parent=None
            ) -> None:
        self._message = message
        super().__init__(parent)

    def setup(self) -> None:
        self._browser = None
        self._bubble = None

    def init_ui(self) -> None:
        """Builds bubble widget with custom background theme"""
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)

        """Pair QTextBrowser and markdown to render content in markdown format"""
        # Layout
        layout = QVBoxLayout(self)

        # Markdown rendering Browser
        md_browser = QTextBrowser(self)
        md_browser.setReadOnly(True)
        md_browser.setOpenExternalLinks(True)
        md_browser.setFrameShape(
                QTextBrowser.Shape.NoFrame
                )

        html = markdown(
                self._message.content,
                extensions=[
                    "fenced_code",
                    "tables",
                    ]
                )

        md_browser.setHtml(html)

        layout.addWidget(md_browser)

        self._browser = md_browser

        # Styling
        match self._message.role:
            case MessageRole.USER:
                self.setObjectName("UserBubble")

            case MessageRole.AETHER:
                self.setObjectName("AetherBubble")

        # Layout
        # layout = QVBoxLayout(self)
        # layout.setContentsMargins(12, 8, 12, 8)
        #
        # # Label/Bubble
        # bubble = QLabel(self._message.content)
        # bubble.setWordWrap(True)
        # bubble.setObjectName("MessageText")
        #
        # # self.setMaximumWidth(700)
        #
        # # Timestamp Container
        # timestamp_container = QWidget(self)
        # timestamp_container.setObjectName("TimestampContainer")
        #
        # timestamp_layout = QHBoxLayout(timestamp_container)
        #
        # # Timestamp
        # if sys.platform == "win32":
        #     formatted_timestamp = self._message.timestamp.strftime("%#I:%M %p")
        # else:
        #     formatted_timestamp = self._message.timestamp.strftime("%-I:%M %p")
        #
        # timestamp = QLabel(formatted_timestamp)
        # timestamp.setObjectName("Timestamp")
        #
        #
        # timestamp_layout.addWidget(timestamp)
        # timestamp_layout.addStretch()
        #
        # layout.addWidget(bubble)
        # layout.addWidget(timestamp_container)
        #
        # self._bubble = bubble
        # self._timestamp = formatted_timestamp

    def style_file(self) -> Path | None:
        """Return the QSS template that paints the panel background."""
        return Path(__file__).resolve().parent / "styles.qss.jinja"
