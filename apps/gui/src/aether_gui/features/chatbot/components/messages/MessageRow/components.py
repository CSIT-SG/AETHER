from pathlib import Path

from aether_gui.utils.ui import StyledComponent
from PySide6.QtWidgets import (
    QApplication,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ..MessageBubble import MessageBubble
from ..Messages import Message, MessageRole
from .utils import ButtonComponent


class MessageRow(StyledComponent):
    """Message Card"""
    def __init__(self, message: Message, parent=None):
        self._message = message
        super().__init__(parent)

    def setup(self) -> None:
        self._copy_btn = None
        self._timestamp = None
        self._name_label = None
        self._bubble = None

    def init_ui(self) -> None:
        """
        # NEW LAYOUT BUILT IN FOLLOWING FORMAT
        # HEADER - USER/AETHER AND TIMESTAMP
        # BODY - MARKDOWN CONTENT (MESSAGEBUBBLE)
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

        card_layout = QVBoxLayout(message_card_container)
        card_layout.setSpacing(0)

        ### HEADER - USER + TIMESTAMP ###
        header_container = QWidget(self)
        header_layout = QHBoxLayout(header_container)
        header_layout.setContentsMargins(0, 0, 0, 2)
        header_layout.setSpacing(8)

        time_label = QLabel(self._message.formatted_timestamp)
        time_label.setObjectName("Timestamp")
        time_label_opacity = QGraphicsOpacityEffect(time_label)
        time_label_opacity.setOpacity(0.60) # 60%
        time_label.setGraphicsEffect(time_label_opacity)

        self._timestamp = time_label

        name_label = QLabel(self._message.role.value)
        match self._message.role:
            case MessageRole.USER:
                header_layout.addStretch()
                header_layout.addWidget(name_label)
                header_layout.addWidget(time_label)

            case MessageRole.AETHER:

                header_layout.addWidget(name_label)
                header_layout.addWidget(time_label)
                header_layout.addStretch()
            case _:
                name_label = QLabel("Unknown")
                raise Exception("MessageRow: Unknown Role")

        name_label.setObjectName("Username")
        self._name_label = name_label

        card_layout.addWidget(header_container)
        ### END HEADER ###

        ### BODY - MARKDOWN CONTENT ###
        bubble = MessageBubble(self._message)
        card_layout.addWidget(bubble)
        self._bubble = bubble
        ### END BODY ###

        ### FOOTER - OTHER WIDGETS (e.g. copy button) ###
        footer_container = QWidget(self)
        footer_layout = QHBoxLayout(footer_container)
        footer_layout.setContentsMargins(0, 2, 0, 0)
        footer_layout.setSpacing(4)

        # NOTE: Future Iteration should move buttons to a footer class which contains all footer buttons
        copy_btn = ButtonComponent(
                icon="\u29C9",
                obj_name="CopyButton",
                tooltip="Copy"
                )
        copy_btn.clicked.connect(self._copy_message)

        self._copy_btn = copy_btn

        footer_layout.addStretch()
        footer_layout.addWidget(copy_btn)

        card_layout.addWidget(footer_container)
        ### END FOOTER ###

        match self._message.role:
            case MessageRole.USER:
                main_layout.addStretch(1)
                main_layout.addWidget(message_card_container, stretch=4)
            case MessageRole.AETHER:
                main_layout.addWidget(message_card_container, stretch=4)
                main_layout.addStretch(1)
            case _:
                main_layout.addStretch()
                main_layout.addWidget(message_card_container)

    def _copy_message(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self._message.content)

    def style_file(self) -> Path | None:
        return Path(__file__).resolve().parent / "styles.qss.jinja"
