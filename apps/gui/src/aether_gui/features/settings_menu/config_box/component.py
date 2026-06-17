from aether_gui.utils.ui import StyledComponent
from aether_utils.config import get_config
from PySide6 import QtWidgets


class ConfigBox(StyledComponent):
    def setup(self) -> None:
        self._contents: str
        self._layout: QtWidgets.QHBoxLayout
        self._container: QtWidgets.QWidget
        self._output_box: QtWidgets.QPlainTextEdit

    def init_ui(self) -> None:
        config_file = get_config()
        output_box = QtWidgets.QPlainTextEdit(self)
        layout = QtWidgets.QHBoxLayout(self)
        layout.addWidget(output_box)
        self._output_box = output_box
        self._layout = layout
        self._contents = config_file.model_dump_json(indent=2)
        self.set_box_content()
        self.setLayout(self._layout)

    def set_box_content(self) -> None:
        """Load config file content into box"""
        self._output_box.setPlainText(self._contents)

    def get_content(self) -> str:
        extracted = self._output_box.toPlainText()
        return extracted
