from pathlib import Path
from typing import Any, cast

from aether_gui.utils.ui import FontPlugin, StyledComponent
from markdown import markdown
from PySide6 import QtCore
from PySide6.QtGui import QColor, QFont, QResizeEvent, QTextCursor, QTextDocument
from PySide6.QtWidgets import QSizePolicy, QTextBrowser, QTextEdit, QVBoxLayout

from ..Messages import Message, MessageRole


class MessageParagraph(StyledComponent):  # type: ignore[misc]
    """Message Paragraphs - contain markdown content"""

    def __init__(self, message: Message, parent: Any = None) -> None:
        self._message = message
        super().__init__(parent, plugins=[FontPlugin()])

    def setup(self) -> None:
        self._browser: QTextBrowser | None = None
        self._paragraph = None

    def init_ui(self) -> None:
        """Builds paragraph widget with custom background theme"""
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)

        """Pair QTextBrowser and markdown to render content in markdown format"""
        # Layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Markdown rendering Browser
        md_browser = QTextBrowser(self)
        md_browser.setObjectName("ChatBox")

        # Style
        md_browser.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)

        md_browser.setReadOnly(True)
        md_browser.setOpenExternalLinks(True)

        md_browser.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        md_browser.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        md_browser.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Fixed,
        )

        md_browser.setFrameShape(QTextBrowser.Shape.NoFrame)

        html = markdown(
            self._message.content,
            extensions=["fenced_code", "tables", "nl2br"],
        )

        md_browser.setHtml(html)

        QtCore.QTimer.singleShot(0, self._adjust_height)

        layout.addWidget(md_browser)

        # Styling
        match self._message.role:
            case MessageRole.USER:
                self.setObjectName("UserParagraph")

            case MessageRole.AETHER:
                self.setObjectName("AetherParagraph")

        self._browser = md_browser

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        QtCore.QTimer.singleShot(0, self._adjust_height)

    def refresh(self) -> None:
        html = markdown(
            self._message.content,
            extensions=["fenced_code", "tables", "nl2br"],
        )

        if self._browser:
            self._browser.setHtml(html)

        QtCore.QTimer.singleShot(0, self._adjust_height)

    def _adjust_height(self) -> None:
        if self._browser is None:
            return

        document = self._browser.document()

        viewport_width = self._browser.viewport().width()
        if viewport_width > 0:
            document.setTextWidth(viewport_width - 10)
        exact_height = int(document.documentLayout().documentSize().height())

        if exact_height > 0:
            self._browser.setFixedHeight(exact_height)
            self.setFixedHeight(exact_height)

        self.updateGeometry()

    def find_matches(self, text: str, case_sensitive: bool = False) -> list[tuple[int, int]]:
        """Return (start, end) character positions of every match in this paragraph."""
        if not text or self._browser is None:
            return []

        document = self._browser.document()
        flags = QTextDocument.FindFlag(0)
        if case_sensitive:
            flags |= QTextDocument.FindFlag.FindCaseSensitively

        matches: list[tuple[int, int]] = []
        cursor = QTextCursor(document)
        while True:
            cursor = document.find(text, cursor, flags)
            if cursor.isNull():
                break
            matches.append((cursor.selectionStart(), cursor.selectionEnd()))
        return matches

    def set_highlights(
        self, ranges: list[tuple[int, int]], current: tuple[int, int] | None
    ) -> None:
        if self._browser is None:
            return

        document = self._browser.document()
        selections = []
        for start, end in ranges:
            cursor = QTextCursor(document)
            cursor.setPosition(start)
            cursor.setPosition(end, QTextCursor.MoveMode.KeepAnchor)

            selection = QTextEdit.ExtraSelection()
            selection_any = cast(Any, selection)
            selection_any.cursor = cursor
            is_current = current is not None and (start, end) == current
            selection_any.format.setBackground(
                QColor("#ffb300") if is_current else QColor("#fff59d")
            )
            selections.append(selection)

        self._browser.setExtraSelections(selections)

    def clear_highlights(self) -> None:
        if self._browser is not None:
            self._browser.setExtraSelections([])

    def style_file(self) -> Path | None:
        """Return the QSS template that paints the panel background."""
        return Path(__file__).resolve().parent / "styles.qss.jinja"

    def on_font_change(self, font: QFont) -> None:
        if self._browser:
            QtCore.QTimer.singleShot(0, self._adjust_height)

    def on_theme_change(self, *, theme, colors) -> None:
        if theme == "dark" and self._message.role == MessageRole.USER:
            self.setProperty("theme", "dark")
        else:
            self.setProperty("theme", "_")

    def _current_font(self) -> QFont:
        """Return the current font.

        Returns:
            The active font, falling back to the shared manager
            if the font plugin is unavailable.
        """

        return cast(QFont, self.get_plugin(FontPlugin).current_font)
