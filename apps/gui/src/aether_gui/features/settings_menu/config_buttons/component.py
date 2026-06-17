from collections.abc import Callable

from aether_gui.utils.ui import StyledComponent
from PySide6 import QtWidgets

from .button_create import ApplyButton, CancelButton, OkButton


class ButtonRow(StyledComponent):
    def __init__(self, get_content: Callable[[], str], on_close: Callable, parent=None) -> None:
        self._get_content = get_content
        self._on_close = on_close
        super().__init__(parent)

    def setup(self) -> None:
        self._layout: QtWidgets.QHBoxLayout
        self._ok: OkButton
        self._apply: ApplyButton
        self._cancel: CancelButton

    def init_ui(self) -> None:
        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        self._layout = layout
        self.setLayout(layout)
        self.set_buttons(self._get_content, self._on_close)

    def set_buttons(self, get_content: Callable, on_close: Callable) -> None:
        ok: OkButton = OkButton(get_content, on_close)
        apply: ApplyButton = ApplyButton(get_content)
        cancel: CancelButton = CancelButton(on_close)
        self._get_content = get_content
        self._layout.addWidget(ok)
        self._layout.addWidget(apply)
        self._layout.addWidget(cancel)
