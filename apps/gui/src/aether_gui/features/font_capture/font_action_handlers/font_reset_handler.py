from typing import cast

import ida_kernwin
from aether_gui.utils.ui import get_shared_font_manager
from PySide6 import QtWidgets


class FontSizeResetHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        super().__init__()

    def activate(self, ctx) -> int:  # type: ignore[override]
        cur = ida_kernwin.get_current_widget()
        if cur is None:
            return 0
        window = cast(QtWidgets.QWidget, ida_kernwin.PluginForm.TWidgetToQtPythonWidget(cur))

        mgr = get_shared_font_manager(window.windowTitle())

        default = QtWidgets.QApplication.font()
        window.setFont(default)
        mgr.set_font(default)

        return 0

    def update(self, ctx) -> int:  # type: ignore[override]
        return ida_kernwin.AST_ENABLE_ALWAYS
