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
        button = QtWidgets.QPushButton(self._label)
        button.clicked.connect(self.action)
        self._button = button

    def write_content(self, path: Path, content: str) ->None:
        with open(path,'w') as f:
            f.write(content)

    @abstractmethod
    def action(self) ->None:
        print(f"ACTION NOT DEFINED BUTTON {self._label} DOES NOTHING")
        raise NotImplementedError
