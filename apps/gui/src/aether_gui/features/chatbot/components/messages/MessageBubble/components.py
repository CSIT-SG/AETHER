from pathlib import Path

from aether_gui.utils.ui import FontPlugin, StyledComponent
from markdown import markdown
from PySide6 import QtCore
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QSizePolicy, QTextBrowser, QTextEdit, QVBoxLayout

from ..Messages import Message, MessageRole


class MessageBubble(StyledComponent):
    """Message Bubbles - contain markdown content"""

    def __init__(self, message: Message, parent=None) -> None:
        self._message = message
        super().__init__(parent, plugins=[FontPlugin()])

    def setup(self) -> None:
        self._browser = None
        self._bubble = None

    def init_ui(self) -> None:
        """Builds bubble widget with custom background theme"""
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)

        """Pair QTextBrowser and markdown to render content in markdown format"""
        # Layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(0)

        # Markdown rendering Browser
        md_browser = QTextBrowser(self)
        md_browser.setObjectName("ChatBox")

        # Style
        md_browser.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Preferred,
        )
        md_browser.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)

        md_browser.setReadOnly(True)
        md_browser.setOpenExternalLinks(True)

        # TODO: Horizontal scrollbar should be in code blocks only
        md_browser.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        md_browser.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        md_browser.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Maximum,
        )

        md_browser.setFrameShape(QTextBrowser.Shape.NoFrame)

        html = markdown(
            self._message.content,
            extensions=[
                "fenced_code",
                "tables",
            ],
        )

        md_browser.setHtml(html)

        self._adjust_height()

        layout.addWidget(md_browser)

        # Styling
        match self._message.role:
            case MessageRole.USER:
                self.setObjectName("UserBubble")

            case MessageRole.AETHER:
                self.setObjectName("AetherBubble")

        self._browser = md_browser

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._adjust_height()

    def _adjust_height(self) -> None:
        if self._browser is None:
            return

        document = self._browser.document()

        # Force document width to match viewport width
        document.setTextWidth(self._browser.viewport().width())

        height = int(document.size().height())

        self._browser.setFixedHeight(height + 10)

    def style_file(self) -> Path | None:
        """Return the QSS template that paints the panel background."""
        return Path(__file__).resolve().parent / "styles.qss.jinja"

    def on_font_change(self, font: QFont) -> None:
        pass

    def _current_font(self) -> QFont:
        """Return the current font.

        Returns:
            The active font, falling back to the shared manager
            if the font plugin is unavailable.
        """

        return self.get_plugin(FontPlugin).current_font
