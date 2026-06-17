from abc import ABC, abstractmethod

from aether_gui.utils.ui import StyledComponent
from PySide6 import QtWidgets


class ConfigButton(ABC, StyledComponent):
    def __init__(
        self, label: str = "I AM NOT SET", parent: QtWidgets.QWidget | None = None
    ) -> None:
        self._label: str = label
        super().__init__(parent)

    def setup(self) -> None:
        self._button: QtWidgets.QPushButton

    def flash_red(self, widget: QtWidgets.QWidget) -> None:
        window = widget.window()
        window.setStyleSheet("QDialog { background-color: #c0392b; }")

    def reset_colour(self, widget: QtWidgets.QWidget) -> None:
        """Restore the window background to its original stylesheet."""
        window = widget.window()
        window.setStyleSheet(window.property("_original_stylesheet") or "")

    def init_ui(self) -> None:
        button = QtWidgets.QPushButton(self._label, self)
        button.clicked.connect(self.action)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(button)
        self.setLayout(layout)
        self._button = button

    @abstractmethod
    def action(self) -> None:
        raise NotImplementedError(f"ACTION NOT DEFINED BUTTON {self._label} DOES NOTHING")
