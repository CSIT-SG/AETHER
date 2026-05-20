from PySide6 import QtCore, QtWidgets


class ChatHistoryView(QtWidgets.QTextEdit):
    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.scrollbar = self.verticalScrollBar()

        self.setReadOnly(True)
        self.setAcceptRichText(True)
        self.setTextInteractionFlags(QtCore.Qt.TextInteractionFlag.TextSelectableByMouse)
        self.setSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)

    def append_message(self, sender: str, message: str) -> None:
        # TODO: Make the stylesheet get fetched from the stylesheets folder and not hardcoded here
        formatted_message = f"<p style='margin: 4px 0;'><b style='color: #007acc;'>{sender}:</b> {message}</p>"
        self.append(formatted_message)

        self.scrollbar.setValue(self.scrollbar.maximum())
