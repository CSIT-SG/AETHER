from typing import cast

import ida_kernwin
from PySide6 import QtWidgets
from shiboken6 import wrapInstance


class SetFontHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        super().__init__()

    def activate(self, ctx) -> int:  # type: ignore[override]
        cur = ida_kernwin.get_current_widget()
        if cur is None:
            return 0
        window = cast(QtWidgets.QWidget, wrapInstance(int(cur), QtWidgets.QWidget))

        ok, font = QtWidgets.QFontDialog.getFont(window.font(), window, "Font")
        if ok:
            window.setFont(font)

        return 0

    def update(self, ctx) -> int:  # type: ignore[overrride]
        return ida_kernwin.AST_ENABLE_ALWAYS
