from typing import cast

import ida_kernwin
from aether_gui.features.chatbot.ui.chat_history_view import ChatHistoryView
from aether_gui.features.chatbot.utils.ui.theme_manager import ThemeManager
from PySide6 import QtWidgets


class MainWindow(ida_kernwin.PluginForm):
    def __init__(self) -> None:
        super().__init__()
        self.parent: QtWidgets.QWidget | None = None
        self.chat_history_view: ChatHistoryView | None = None
        self.theme_manager = ThemeManager()

    def OnCreate(self, form: object) -> None:
        self.parent = cast(QtWidgets.QWidget, ida_kernwin.PluginForm.FormToPyQtWidget(form))
        layout = QtWidgets.QVBoxLayout(self.parent)
        layout.setContentsMargins(8, 8, 8, 8)

        self.chat_history_view = ChatHistoryView()
        self.chat_history_view.setObjectName("ChatHistoryView")
        layout.addWidget(self.chat_history_view)
        layout.setStretchFactor(self.chat_history_view, 1)

        self.parent.setStyleSheet(self.theme_manager.current_theme)

    def OnClose(self, form: object) -> None:
        pass
