from pathlib import Path
from typing import Any, cast

from aether_gui.utils.ui import FontPlugin, StyledComponent
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ..MessageParagraph import MessageParagraph
from ..Messages import Message, MessageRole
from .utils import ButtonComponent


class MessageColumn(StyledComponent):  # type: ignore[misc]
    """Message Card"""

    def __init__(self, message: Message, parent: Any = None) -> None:
        self._last_message_data = message
        super().__init__(parent, plugins=[FontPlugin()])

    def setup(self) -> None:
        self._copy_btn: ButtonComponent | None = None
        self._timestamp: QLabel | None = None
        self._name_label: QLabel | None = None
        self._last_paragraph: MessageParagraph | None = None

    def init_ui(self) -> None:
        """
        # NEW LAYOUT BUILT IN FOLLOWING FORMAT
        # HEADER - USER/AETHER AND TIMESTAMP
        # BODY - MARKDOWN CONTENT (MESSAGEParagraph)
        # FOOTER - COPY BUTTON and future button widget implementations
        """

        # Layout
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        message_card_container = QWidget(self)
        message_card_container.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Preferred,
        )

        self.card_layout = QVBoxLayout(message_card_container)
        self.card_layout.setSpacing(0)

        ### HEADER - USER + TIMESTAMP ###
        header_container = QWidget(self)
        header_layout = QHBoxLayout(header_container)
        header_layout.setContentsMargins(0, 0, 0, 2)
        header_layout.setSpacing(8)

        time_label = QLabel(self._last_message_data.formatted_timestamp)
        time_label.setObjectName("Timestamp")
        time_label_opacity = QGraphicsOpacityEffect(time_label)
        time_label_opacity.setOpacity(0.60)  # 60%
        time_label.setGraphicsEffect(time_label_opacity)

        self._timestamp = time_label

        name_label = QLabel(self._last_message_data.role.value)
        match self._last_message_data.role:
            case MessageRole.USER:
                header_layout.addStretch()
                header_layout.addWidget(name_label, 0, Qt.AlignmentFlag.AlignVCenter)
                header_layout.addWidget(time_label, 0, Qt.AlignmentFlag.AlignVCenter)

            case MessageRole.AETHER:
                header_layout.addWidget(name_label, 0, Qt.AlignmentFlag.AlignVCenter)
                header_layout.addWidget(time_label, 0, Qt.AlignmentFlag.AlignVCenter)
                header_layout.addStretch()
            case _:
                name_label = QLabel("Unknown")
                raise Exception("MessageRow: Unknown Role")

        name_label.setObjectName("Username")
        self._name_label = name_label

        self.card_layout.addWidget(header_container)
        ### END HEADER ###

        ### BODY - MARKDOWN CONTENT ###
        paragraph = MessageParagraph(self._last_message_data, self)
        self.card_layout.addWidget(paragraph)
        self._last_paragraph = paragraph
        ### END BODY ###

        ### FOOTER - OTHER WIDGETS (e.g. copy button) ###
        footer_container = QWidget(self)
        footer_layout = QHBoxLayout(footer_container)
        footer_layout.setContentsMargins(0, 2, 0, 0)
        footer_layout.setSpacing(4)

        # NOTE: Future Iteration should move buttons to a footer class which contains all footer buttons
        copy_btn = ButtonComponent(icon="\u29c9", obj_name="CopyButton", tooltip="Copy")
        copy_btn.clicked.connect(self._copy_message)

        self._copy_btn = copy_btn

        footer_layout.addStretch()
        footer_layout.addWidget(copy_btn)

        self.card_layout.addWidget(footer_container)
        ### END FOOTER ###

        match self._last_message_data.role:
            case MessageRole.USER:
                main_layout.addStretch(1)
                main_layout.addWidget(message_card_container, stretch=4)
            case MessageRole.AETHER:
                main_layout.addStretch()
                main_layout.addWidget(message_card_container, stretch=1)
                main_layout.addStretch()
            case _:
                main_layout.addStretch()
                main_layout.addWidget(message_card_container)

    def _copy_message(self) -> None:
        clipboard = QApplication.clipboard()
        clipboard.setText(self._last_message_data.content)

    def _adjust_height(self) -> None:
        if self.card_layout:
            self.card_layout.invalidate()

        self.adjustSize()
        self.updateGeometry()

    def add_new_paragraph(self, message: Message) -> None:
        if self._last_paragraph:
            paragraph = MessageParagraph(message, self)
            footer_index = self.card_layout.count() - 1
            self.card_layout.insertWidget(footer_index, paragraph)
            self._last_message_data = message
            self._last_paragraph = paragraph

            self._adjust_height()

    def append_last_paragraph(self, message: str) -> None:
        self._last_message_data.content += message
        if self._last_paragraph:
            self._last_paragraph.refresh()

    def style_file(self) -> Path | None:
        return Path(__file__).resolve().parent / "styles.qss.jinja"

    def on_font_change(self, font: QFont) -> None:
        self._adjust_height()

    def _current_font(self) -> QFont:
        """Return the current font.

        Returns:
            The active font, falling back to the shared manager
            if the font plugin is unavailable.
        """

        return cast(QFont, self.get_plugin(FontPlugin).current_font)
