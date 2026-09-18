from typing import cast

import ida_kernwin
from aether_gui.utils.ui import get_shared_font_manager
from PySide6 import QtWidgets
from PySide6.QtGui import QFont


class FontSizeIncreaseHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        super().__init__()

    def activate(self, ctx) -> int:  # type: ignore[override]
        cur = ida_kernwin.get_current_widget()
        if cur is None:
            return 0
        window = cast(QtWidgets.QWidget, ida_kernwin.PluginForm.TWidgetToQtPythonWidget(cur))

        mgr = get_shared_font_manager(window.windowTitle())

        f = QFont(mgr.get_current_font())
        size = f.pointSize() if f.pointSize() > 0 else 10
        f.setPointSize(min(72, size + 1))

        window.setFont(f)
        mgr.set_font(f)

        return 0

    def update(self, ctx) -> int:  # type: ignore[override]
        return ida_kernwin.AST_ENABLE_ALWAYS
