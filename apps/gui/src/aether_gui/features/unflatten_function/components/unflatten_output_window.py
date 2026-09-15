from typing import cast

import ida_kernwin
from aether_gui.utils.constants import WINDOW_PREFIX
from PySide6 import QtGui, QtWidgets


class UnflattenOutputWindow(ida_kernwin.PluginForm):
    """Dockable view with a single block of replaceable text."""

    def __init__(
        self, title: str = f"{WINDOW_PREFIX} Unflatten Function", initial: str = "Loading..."
    ) -> None:
        super().__init__()
        self._title: str = title
        self._pending: str = initial
        self._text: QtWidgets.QPlainTextEdit | None = None

    def OnCreate(self, form: int) -> None:
        parent: QtWidgets.QWidget = cast(QtWidgets.QWidget, self.FormToPyQtWidget(form))

        self._text = QtWidgets.QPlainTextEdit()
        self._text.setReadOnly(True)
        self._text.setFont(QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont))
        self._text.setPlainText(self._pending)

        layout: QtWidgets.QVBoxLayout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(4, 4, 4, 4)
        layout.addWidget(self._text)
        parent.setLayout(layout)

    def OnClose(self, form: int) -> None:
        self._text = None

    def show(self) -> None:
        self.Show(
            self._title,
            options=ida_kernwin.PluginForm.WOPN_PERSIST | ida_kernwin.PluginForm.WOPN_DP_RIGHT,
        )

    def set_text(self, text: str) -> None:
        """Thread-safe. Call from anywhere, including a worker thread."""
        print(text)

        def _apply() -> int:
            if self._text is not None:
                self._text.setPlainText(text)
            else:
                self._pending = text  # view not built (or closed) yet
            return 1

        ida_kernwin.execute_sync(_apply, ida_kernwin.MFF_FAST)
