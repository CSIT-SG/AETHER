import os
from typing import cast

import ida_kernwin
from aether_gui.features.chatbot.ui.chat_history_view import ChatHistoryView
from PySide6 import QtCore, QtWidgets


class MainWindow(ida_kernwin.PluginForm):
    def __init__(self) -> None:
        super().__init__()
        self.parent: QtWidgets.QWidget | None = None
        self.chat_history_view: ChatHistoryView | None = None

    def OnCreate(self, form: object) -> None:
        self.parent = cast(QtWidgets.QWidget, ida_kernwin.PluginForm.FormToPyQtWidget(form))
        layout = QtWidgets.QVBoxLayout(self.parent)
        layout.setContentsMargins(8, 8, 8, 8)

        label = QtWidgets.QLabel("AETHER ChatBot")
        label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.apply_theme(label)
        layout.addWidget(label)

        self.chat_history_view = ChatHistoryView()
        layout.addWidget(self.chat_history_view)
        layout.setStretchFactor(self.chat_history_view, 1)

    def apply_theme(self, label: QtWidgets.QLabel) -> None:
        if not self.parent:
            return

        is_dark = "dark" in os.environ.get("IDA_THEME", "").lower()

        # TO BE DONE: Make the stylesheet get fetched from the stylesheets folder and not hardcoded here
        if is_dark:
            self.parent.setStyleSheet("background-color: #2b2b2b; color: #ffffff;")
            label.setStyleSheet("color: #ffffff;")
        else:
            self.parent.setStyleSheet("background-color: #ffffff; color: #000000;")
            label.setStyleSheet("color: #000000;")

    def OnClose(self, form: object) -> None:
        pass
