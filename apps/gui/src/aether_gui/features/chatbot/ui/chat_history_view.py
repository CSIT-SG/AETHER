import os

from PySide6 import QtCore, QtWidgets

from .scrollbar import ScrollBar


class ChatHistoryView(QtWidgets.QTextEdit):
    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self.scrollbar = ScrollBar(QtCore.Qt.Orientation.Vertical, self)
        self.setVerticalScrollBar(self.scrollbar)
        self.setLayoutDirection(QtCore.Qt.LayoutDirection.LeftToRight)
        self.setup()

    def setup(self) -> None:
        self.setReadOnly(True)
        self.setAcceptRichText(True)
        self.setTextInteractionFlags(QtCore.Qt.TextInteractionFlag.TextSelectableByMouse)
        self.setSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)

        self.apply_theme()

    def append_message(self, sender: str, message: str) -> None:
        # TO BE DONE: Make the stylesheet get fetched from the stylesheets folder and not hardcoded here
        formatted_message = f"<p style='margin: 4px 0;'><b style='color: #007acc;'>{sender}:</b> {message}</p>"
        self.append(formatted_message)

        self.scrollbar.setValue(self.scrollbar.maximum())

    def apply_theme(self) -> None:
        is_dark = "dark" in os.environ.get("IDA_THEME", "").lower()

        # TO BE DONE: Make the stylesheet get fetched from the stylesheets folder and not hardcoded here
        if is_dark:
            self.setStyleSheet("background-color: #2b2b2b; color: #ffffff;")
        else:
            self.setStyleSheet("background-color: #ffffff; color: #000000;")
