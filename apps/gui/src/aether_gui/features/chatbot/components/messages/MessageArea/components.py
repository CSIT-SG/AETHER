from pathlib import Path
from typing import cast

from aether_gui.utils.ui import StyledComponent
from PySide6 import QtCore
from PySide6.QtWidgets import QFrame, QScrollArea, QVBoxLayout, QWidget

from ..MessageRow import MessageRow
from ..Messages import Message


class MessageArea(StyledComponent):
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

    def append_message(self, message:Message):
        card = MessageRow(message)
        messages_layout = cast(QVBoxLayout, self._messages_layout)
        messages_layout.addWidget(card)

        QtCore.QTimer.singleShot(
                0,
                self.scroll_to_bottom,
            )

    # FIX: Scrollbar doesn't work yet
    def scroll_to_bottom(self, min_val, max_val) -> None:
        scrollbar = cast(QScrollArea, self._scroll_area).verticalScrollBar()

        # Scroll to bottom only if user is already close to bottom
        if scrollbar.value() >= max_val - 50:
            scrollbar.setValue(max_val)


    def style_file(self) -> Path | None:
        return Path(__file__).resolve().parent / "styles.qss.jinja"
