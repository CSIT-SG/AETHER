from pathlib import Path
from typing import cast

from aether_gui.utils.ui import StyledComponent
from PySide6 import QtCore
from PySide6.QtWidgets import QFrame, QScrollArea, QVBoxLayout, QWidget

from ..MessageRow import MessageRow
from ..Messages import Message


class MessageArea(StyledComponent):  # type: ignore[misc]
    """Message area where message bubbles are placed"""

    def setup(self) -> None:
        self._scroll_area: QScrollArea | None = None
        self._messages_container: QWidget | None = None
        self._messages_layout: QVBoxLayout | None = None

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
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)

        # Style Scrollbar
        scrollbar = scroll_area.verticalScrollBar()
        scrollbar.rangeChanged.connect(self.scroll_to_bottom)
        scrollbar.setObjectName("ChatScrollBar")

        # Messages layout (for scrollable layout)
        messages_container = QWidget(self)

        messages_layout = QVBoxLayout(messages_container)
        messages_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)

        messages_layout.addStretch()
        messages_layout.setSpacing(12)

        scroll_area.setWidget(messages_container)
        layout.addWidget(scroll_area)

        self._scroll_area = scroll_area
        self._messages_container = messages_container
        self._messages_layout = messages_layout

    def add_new_message_bubble(self, message: Message) -> None:
        """Creates new message row"""
        card = MessageRow(message, self)
        messages_layout = cast(QVBoxLayout, self._messages_layout)
        messages_layout.addWidget(card)

        QtCore.QTimer.singleShot(
            0,
            self.scroll_to_bottom,
        )

    def add_new_paragraph(self, message: Message) -> None:
        """Calls add new paragraph on current message row"""
        if not self._messages_layout:
            return

        layout = self._messages_layout.itemAt(self._messages_layout.count() - 1)
        if not layout:
            return

        last_widget = layout.widget()
        message_row = cast(MessageRow, last_widget)
        message_row.add_new_paragraph(message)

        QtCore.QTimer.singleShot(
            0,
            self.scroll_to_bottom,
        )

    def append_to_last_paragraph(self, message: str) -> None:
        """Calls append paragraph on current message row"""
        if not self._messages_layout:
            return

        layout = self._messages_layout.itemAt(self._messages_layout.count() - 1)
        if not layout:
            return

        last_widget = layout.widget()
        message_row = cast(MessageRow, last_widget)
        message_row.append_last_paragraph(message)

        QtCore.QTimer.singleShot(
            0,
            self.scroll_to_bottom,
        )

    # FIX: Scrollbar doesn't work yet
    def scroll_to_bottom(self, min_val: int, max_val: int) -> None:
        scrollbar = cast(QScrollArea, self._scroll_area).verticalScrollBar()

        # Scroll to bottom only if user is already close to bottom
        if scrollbar.value() >= max_val - 50:
            scrollbar.setValue(max_val)

    def style_file(self) -> Path | None:
        return Path(__file__).resolve().parent / "styles.qss.jinja"
