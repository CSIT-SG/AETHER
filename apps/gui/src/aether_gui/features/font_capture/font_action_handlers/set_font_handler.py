from typing import cast

import ida_kernwin
from aether_gui.utils.ui import get_shared_font_manager
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

        mgr = get_shared_font_manager(window.windowTitle())

        if window.font() != mgr.get_current_font():
            window.setFont(mgr.get_current_font())

        ok, font = QtWidgets.QFontDialog.getFont(window.font(), window, "Font")
        if ok:
            window.setFont(font)
            mgr.set_font(font)

        return 0

    def update(self, ctx) -> int:  # type: ignore[overrride]
        return ida_kernwin.AST_ENABLE_ALWAYS
