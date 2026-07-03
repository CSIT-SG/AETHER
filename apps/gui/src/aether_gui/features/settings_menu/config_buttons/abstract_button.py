from abc import ABC, abstractmethod

from aether_gui.utils.ui import StyledComponent
from PySide6 import QtWidgets

from ..constants import UNDEFINED_BUTTON_ACTION_ERROR, UNSET_BUTTON_LABEL


class ConfigButton(ABC, StyledComponent):
    def __init__(
        self, label: str = UNSET_BUTTON_LABEL, parent: QtWidgets.QWidget | None = None
    ) -> None:
        self._label: str = label
        super().__init__(parent)

    def setup(self) -> None:
        self._button: QtWidgets.QPushButton

    def init_ui(self) -> None:
        button = QtWidgets.QPushButton(self._label, self)
        button.clicked.connect(self.action)
        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(button)
        self.setLayout(layout)
        self._button = button

    @abstractmethod
    def action(self) -> None:
        raise NotImplementedError(UNDEFINED_BUTTON_ACTION_ERROR.format(label=self._label))
