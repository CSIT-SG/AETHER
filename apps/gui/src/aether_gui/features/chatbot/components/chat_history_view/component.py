from pathlib import Path

from aether_gui.features.chatbot.components.chat_input.component import ChatInput
from aether_gui.utils.ui import StyledComponent
from aether_gui.utils.ui.plugins import Theme, ThemeColors
from PySide6 import QtCore, QtWidgets

from ..scrollbar import ScrollBar


class ChatHistoryView(StyledComponent):
    """Scrollable chat transcript with a themed custom scrollbar."""

    def setup(self) -> None:
        self._text: QtWidgets.QTextEdit | None = None
        self._scrollbar_component: ScrollBar | None = None
        self._messages: list[tuple[str, str]] = []

    def init_ui(self) -> None:
        """Build the text view and custom scrollbar."""
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)

        # Main Layout
        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        #Chat Layout
        chat_container = QtWidgets.QWidget(self)
        chat_layout = QtWidgets.QVBoxLayout(chat_container)
        chat_layout.setContentsMargins(0, 0, 0, 0)
        chat_layout.setSpacing(0)
        # Text view
        text = QtWidgets.QTextEdit(self)
        text.setObjectName("ChatHistoryText")
        text.setReadOnly(True)
        text.setAcceptRichText(True)
        text.setTextInteractionFlags(QtCore.Qt.TextInteractionFlag.TextSelectableByMouse)
        text.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        text.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        text.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Expanding,
            QtWidgets.QSizePolicy.Policy.Expanding,
        )
        chat_layout.addWidget(text)

        # Chat Input
        chat_input = ChatInput(chat_container)
        chat_layout.addWidget(chat_input)

        layout.addWidget(chat_container)

        # Scrollbar
        scrollbar_component = ScrollBar(QtCore.Qt.Orientation.Vertical, self)
        layout.addWidget(scrollbar_component)

        layout.setStretchFactor(chat_container, 1)
        layout.setStretchFactor(scrollbar_component, 0)
        self._text = text
        self._scrollbar_component = scrollbar_component

    def plugins_ready(self) -> None:
        if self._text is None or self._scrollbar_component is None:
            return
        # Bind the themed scrollbar to the text viewport.
        self._scrollbar_component.bind_to(self._text)

    def style_file(self) -> Path | None:
        """Return the QSS template for the chat background and text styling."""
        return Path(__file__).resolve().parent / "styles.qss.jinja"

    def template_file(self) -> Path | None:
        """Return the HTML template used to render each chat line."""
        return Path(__file__).resolve().parent / "template.html.jinja"

    def append_message(self, sender: str, message: str) -> None:
        """Render a message via the HTML template and append it to the view."""
        if self._text is None:
            return
        self._messages.append((sender, message))
        rendered = self.render_html(sender=sender, message=message)
        if rendered.strip():
            self._text.append(rendered)
        text_scrollbar = self._text.verticalScrollBar()
        text_scrollbar.setValue(text_scrollbar.maximum())

    def on_theme_change(self, *, theme: Theme, colors: ThemeColors) -> None:
        """Re-render cached messages so HTML colors track the new theme."""
        if self._text is None:
            return
        self._text.clear()
        for sender, message in self._messages:
            rendered = self.render_html(sender=sender, message=message)
            if rendered.strip():
                self._text.append(rendered)
        text_scrollbar = self._text.verticalScrollBar()
        text_scrollbar.setValue(text_scrollbar.maximum())


def create_chat_history_view(parent: QtWidgets.QWidget | None = None) -> ChatHistoryView:
    return ChatHistoryView(parent)
