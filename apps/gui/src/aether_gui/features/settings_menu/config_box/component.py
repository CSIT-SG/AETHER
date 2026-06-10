from aether_gui.utils.ui import StyledComponent
from aether_utils.config import CONFIG_FILE
from PySide6 import QtWidgets

with open(CONFIG_FILE) as f:
            CONTENTS: str = f.read()

class ConfigBox(StyledComponent):
    def setup(self) -> None:
        self._layout: QtWidgets.QHBoxLayout
        self._container: QtWidgets.QWidget
        self._output_box: QtWidgets.QPlainTextEdit

    def init_ui(self) -> None:
        container = QtWidgets.QWidget()
        output_box = QtWidgets.QPlainTextEdit()
        layout = QtWidgets.QHBoxLayout(container)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.addWidget(output_box)
        self._container = container
        self._output_box = output_box
        self._layout = layout

    def set_box_content(self) -> None:
        """Load config file content into box"""
        self._output_box.setPlainText(CONTENTS)


def create_config_box() -> ConfigBox:
    return ConfigBox()
