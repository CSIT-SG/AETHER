from pathlib import Path

from aether_gui.utils.ui import StyledComponent
from PySide6 import QtCore, QtWidgets

from ..scrollbar import ScrollBar


class ChatHistoryView(StyledComponent):
    """Scrollable chat transcript with a themed custom scrollbar."""

    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        """Initialize state and defer UI construction to init_ui()."""
        self._text: QtWidgets.QTextEdit | None = None
        self._scrollbar_component: ScrollBar | None = None
        self._messages: list[tuple[str, str]] = []
        super().__init__(parent)

    def init_ui(self) -> None:
        """Build the text view and bind the custom scrollbar."""
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)
        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

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
        layout.addWidget(text)

        scrollbar_component = ScrollBar(QtCore.Qt.Orientation.Vertical, self)
        layout.addWidget(scrollbar_component)

        layout.setStretchFactor(text, 1)
        layout.setStretchFactor(scrollbar_component, 0)
        self._text = text
        self._scrollbar_component = scrollbar_component
        # Bind the themed scrollbar to the text viewport.
        self._scrollbar_component.bind_to(text)

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

    def on_theme_changed(self, *, colors, mode) -> None:
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
