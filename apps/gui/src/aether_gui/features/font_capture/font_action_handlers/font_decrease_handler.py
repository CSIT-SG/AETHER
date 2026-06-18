from typing import cast

import ida_kernwin
from PySide6 import QtWidgets
from shiboken6 import wrapInstance


class FontSizeDecreaseHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        super().__init__()

    def activate(self, ctx) -> int:  # type: ignore[override]
        cur = ida_kernwin.get_current_widget()
        if cur is None:
            return 0
        window = cast(QtWidgets.QWidget, wrapInstance(int(cur), QtWidgets.QWidget))

        f = window.font()
        size = f.pointSize() if f.pointSize() > 0 else 10
        f.setPointSize(max(4, size - 1))
        window.setFont(f)

        return 0

    def update(self, ctx) -> int:  # type: ignore[override]
        return ida_kernwin.AST_ENABLE_ALWAYS
