from pathlib import Path

from aether_gui.utils.ui import StyledComponent
from aether_gui.utils.ui.plugins.theme_plugin.types import Theme, ThemeColors
from PySide6 import QtCore, QtWidgets
from PySide6.QtGui import QTextOption


class ChatInput(StyledComponent):
    """Chat bar to enter user input"""

    def __init__(self, parent: QtWidgets.QWidget | None = None,) -> None:
        super().__init__(parent)

    def setup(self) -> None:
        self._textbox: QtWidgets.QTextEdit | None = None
        self._send_button: QtWidgets.QPushButton | None = None

    def init_ui(self) -> None:
        """Build chat input widget as expandable text area instead of single line input"""
        # self.setAttribute(QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)

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
                QtWidgets.QSizePolicy.Policy.Expanding,
                QtWidgets.QSizePolicy.Policy.Minimum
                )

        textbox.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        textbox.setLineWrapMode(QtWidgets.QTextEdit.LineWrapMode.WidgetWidth)

        textbox.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        textbox.textChanged.connect(self._adjust_height)

        # textbox.setViewportMargins(0, 0, 40, 0)

        textbox.setAttribute(QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)
        layout.addWidget(textbox, 1)
        self._textbox = textbox


        # Submit Button
        submit_btn = QtWidgets.QPushButton("\u2191", self)
        submit_btn.setObjectName("SendButton")
        # submit_btn.setAttribute(QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)
        # submit_btn.setFixedSize(32, 32)
        layout.addWidget(submit_btn, 0, QtCore.Qt.AlignmentFlag.AlignRight | QtCore.Qt.AlignmentFlag.AlignBottom)

        # submit_btn.clicked.connect() #TODO: ADD FUNCTION
        self._send_button = submit_btn

        # Call _adjust_height to adjust height to single line
        self._adjust_height()


    def _adjust_height(self):
        document_height = (
                self._textbox.document()
                .documentLayout()
                .documentSize()
                .height()
                )

        height = min(
                max(40, int(document_height + 10)),
                120
                )

        self._textbox.setFixedHeight(height)

    # def _reposition_button(self):
    #     margin = 8
    #
    #     self._send_button.move(
    #             self._textbox.viewport().width() - self._send_button.width() - margin,
    #             self._textbox.height() + self._send_button.height() + margin
    #             )

    def on_theme_change(self, *, theme: Theme, colors: ThemeColors) -> None:
        pass

    def style_file(self) -> Path | None:
        return Path(__file__).with_name("styles.qss.jinja")

def create_chat_input(parent: QtWidgets.QWidget | None = None) -> ChatInput:
    return ChatInput(parent=parent)
