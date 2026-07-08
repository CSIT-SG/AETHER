from collections.abc import Sequence

from aether_gui.utils.ui import StyledComponent
from PySide6 import QtCore, QtWidgets

from .button_base import ConfigButton


class ButtonRow(StyledComponent):
    def __init__(
        self,
        buttons: Sequence[ConfigButton],
        parent=None,
    ) -> None:
        self._buttons = list(buttons)
        super().__init__(parent)

    def setup(self) -> None:
        self._layout: QtWidgets.QHBoxLayout

    def init_ui(self) -> None:
        layout = QtWidgets.QHBoxLayout(self)
        layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight)
        layout.setContentsMargins(0, 0, 0, 0)
        self._layout = layout
        for btn in self._buttons:
            btn.setSizePolicy(
                QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed
            )
            self._layout.addWidget(btn)
        self.setLayout(self._layout)


def create_button_row(
    buttons: Sequence[ConfigButton],
    parent: QtWidgets.QWidget | None = None,
) -> ButtonRow:
    return ButtonRow(buttons, parent=parent)
