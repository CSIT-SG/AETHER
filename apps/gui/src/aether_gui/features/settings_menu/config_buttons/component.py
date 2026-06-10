from collections.abc import Callable

from aether_gui.utils.ui import StyledComponent
from PySide6 import QtWidgets

from .button_create import ApplyButton, CancelButton, OkButton


class ButtonRow(StyledComponent):

    def setup(self) -> None:
        self._layout: QtWidgets.QHBoxLayout
        self._container: QtWidgets.QWidget


    def init_ui(self) -> None:
        layout = QtWidgets.QHBoxLayout(self)
        container = QtWidgets.QWidget()
        layout.setContentsMargins(8,8,8,8)
        layout.setSpacing(8)
        self._layout = layout
        self._container = container


    def set_buttons(self, get_content: Callable, on_close: Callable) -> None:
        ok: OkButton = OkButton(get_content, on_close)
        apply: ApplyButton = ApplyButton(get_content)
        cancel: CancelButton = CancelButton(on_close)
        self._layout.addWidget(ok)
        self._layout.addWidget(apply)
        self._layout.addWidget(cancel)
        self._container.setLayout(self._layout)
