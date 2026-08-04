import copy
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from aether_gui.utils.chat_session import ChatSession
from aether_gui.utils.ui import StyledComponent
from PySide6 import QtCore
from PySide6.QtWidgets import QFrame, QLabel, QScrollArea, QStackedWidget, QVBoxLayout, QWidget

from ..MessageColumn import MessageColumn
from ..Messages import Message, MessageRole


class MessageArea(StyledComponent):  # type: ignore[misc]
    """Message area where message bubbles are placed"""

    def __init__(self, session: ChatSession, *, parent: Any = None):
        self._session = session
        super().__init__(parent)

    def setup(self) -> None:
        self._scroll_area: QScrollArea | None = None
        self._messages_container: QWidget | None = None
        self._messages_layout: QVBoxLayout | None = None
        self._stack: QStackedWidget | None = None
        self._empty_state: QWidget | None = None

    def init_ui(self) -> None:
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # --- Stack holds either the empty-state CTA or the scroll area ---
        stack = QStackedWidget(self)

        # Empty state (centered CTA)
        empty_state = QWidget(self)
        empty_layout = QVBoxLayout(empty_state)
        empty_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)

        cta_label = QLabel("No conversation loaded.\nType something to get started!", empty_state)
        cta_label.setObjectName("EmptyStateLabel")
        cta_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        empty_layout.addWidget(cta_label)

        self._empty_state = empty_state

        # Scroll Area (existing)
        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)

        scrollbar = scroll_area.verticalScrollBar()
        scrollbar.rangeChanged.connect(self.scroll_to_bottom)
        scrollbar.setObjectName("ChatScrollBar")

        messages_container = QWidget(self)
        messages_layout = QVBoxLayout(messages_container)
        messages_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)
        messages_layout.addStretch()
        messages_layout.setSpacing(12)

        scroll_area.setWidget(messages_container)

        stack.addWidget(empty_state)  # index 0
        stack.addWidget(scroll_area)  # index 1
        stack.setCurrentIndex(0)  # start empty

        layout.addWidget(stack)

        self._scroll_area = scroll_area
        self._messages_container = messages_container
        self._messages_layout = messages_layout
        self._stack = stack

    def add_new_message_column(
        self, message: str, id: str, timestamp: datetime, role: MessageRole
    ) -> None:
        """Creates new message column"""
        message_data = Message(id=id, role=role, content=message, timestamp=timestamp)
        card = MessageColumn(message_data, self)
        messages_layout = cast(QVBoxLayout, self._messages_layout)
        messages_layout.addWidget(card)

        if self._stack:
            self._stack.setCurrentIndex(1)  # switch to message list

        QtCore.QTimer.singleShot(0, self.scroll_to_bottom)

        for data in self._session.messages:
            if data.id == id:
                return
        self._session.add_message(copy.copy(message_data))

    def add_paragraph_to_last_column(self, message: str, role: MessageRole) -> None:
        """Add a new paragraph to the last message column."""
        last_widget = self._get_last_widget()

        if last_widget:
            message_data = Message(
                id=str(uuid4()), role=role, content=message, timestamp=datetime.now()
            )
            message_column = cast(MessageColumn, last_widget)
            message_column.add_new_paragraph(message_data)
            self._session.append_to_last_message("\n\n" + message_data.content)

    def append_to_last_paragraph_of_last_column(self, message: str) -> None:
        """Append text to the last paragraph of the last message column."""
        last_widget = self._get_last_widget()

        if last_widget:
            message_column = cast(MessageColumn, last_widget)
            message_column.append_last_paragraph(message)

        self._session.append_to_last_message(message)

    def load_message_history(self) -> None:
        if not self._session.messages:
            return

        for msg in self._session.messages:
            self.add_new_message_column(
                message=msg.content, id=msg.id, timestamp=msg.timestamp, role=msg.role
            )

    def _get_last_widget(self) -> QWidget | None:
        if not self._messages_layout:
            return None

        layout = self._messages_layout.itemAt(self._messages_layout.count() - 1)
        if not layout:
            return None

        return layout.widget()

    def scroll_to_bottom(self) -> None:
        scrollbar = cast(QScrollArea, self._scroll_area).verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def style_file(self) -> Path | None:
        return Path(__file__).resolve().parent / "styles.qss.jinja"
