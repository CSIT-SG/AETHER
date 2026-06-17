from abc import ABC, abstractmethod
from pathlib import Path

from aether_gui.utils.ui import StyledComponent
from PySide6 import QtWidgets


class ConfigButton(ABC, StyledComponent):
    def __init__(self, label: str = "I AM NOT SET", parent: QtWidgets.QWidget | None = None) -> None:
        self._label: str = label
        super().__init__(parent)


    def setup(self) -> None:
        self._button: QtWidgets.QPushButton


    def init_ui(self) -> None:
        button = QtWidgets.QPushButton(self._label, self)
        button.clicked.connect(self.action)
        self._button = button

    @abstractmethod
    def action(self) ->None:
        print(f"ACTION NOT DEFINED BUTTON {self._label} DOES NOTHING")
        raise NotImplementedError
