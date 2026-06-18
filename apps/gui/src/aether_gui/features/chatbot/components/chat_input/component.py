from pathlib import Path
from typing import cast

from aether_gui.utils.ui import FontPlugin, StyledComponent
from PySide6 import QtCore, QtWidgets
from PySide6.QtGui import QFont, QKeySequence, QShortcut, QTextOption


class ChatInput(StyledComponent):
    """Chat bar to enter user input"""

    # Submit Signal
    submitted = QtCore.Signal(str)

    def __init__(
        self,
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__(parent, plugins=[FontPlugin()])

    def setup(self) -> None:
        self._textbox: QtWidgets.QTextEdit | None = None
        self._send_button: QtWidgets.QPushButton | None = None

    def init_ui(self) -> None:
        """Build chat input widget as expandable text area instead of single line input"""

        # Layout
        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Textbox Widget
        textbox = QtWidgets.QTextEdit(self)
        textbox.setPlaceholderText("Ask meee!")

        textbox.setAcceptRichText(True)

        textbox.setMinimumHeight(40)
        textbox.setMaximumHeight(120)
        textbox.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Minimum
        )

        textbox.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        textbox.setLineWrapMode(QtWidgets.QTextEdit.LineWrapMode.WidgetWidth)

        textbox.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        textbox.textChanged.connect(self._adjust_height)

        textbox.setAttribute(QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)
        layout.addWidget(textbox, 1)

        self._textbox = textbox

        # Submit Button
        submit_btn = QtWidgets.QPushButton("\u2191", self._textbox)
        submit_btn.clicked.connect(self._submit)
        submit_btn.setObjectName("SendButton")
        layout.addWidget(
            submit_btn, 0, QtCore.Qt.AlignmentFlag.AlignRight | QtCore.Qt.AlignmentFlag.AlignBottom
        )
        # Map "Ctrl+Enter" to submit_btn
        shortcut = QShortcut(QKeySequence("Ctrl+Return"), self)
        shortcut.activated.connect(submit_btn.animateClick)

        self._send_button = submit_btn

        # Call _adjust_height to adjust height to single line
        self._adjust_height()

    def _adjust_height(self):
        textbox = cast(QtWidgets.QTextEdit, self._textbox)

        document_height = textbox.document().documentLayout().documentSize().height()

        height = min(max(40, int(document_height + 10)), 120)

        textbox.setFixedHeight(height)

    def _submit(self) -> None:
        textbox = cast(QtWidgets.QTextEdit, self._textbox)
        text = textbox.toPlainText().strip()

        if not text:
            return

        self.submitted.emit(text)

        textbox.clear()

        textbox.setFocus()

    def style_file(self) -> Path | None:
        return Path(__file__).with_name("styles.qss.jinja")

    def on_font_change(self, font: QFont) -> None:
        pass

    def _current_font(self) -> QFont:
        """Return the current font.

        Returns:
            The active font, falling back to the shared manager
            if the font plugin is unavailable.
        """

        return self.get_plugin(FontPlugin).current_font


def create_chat_input(parent: QtWidgets.QWidget | None = None) -> ChatInput:
    return ChatInput(parent=parent)
