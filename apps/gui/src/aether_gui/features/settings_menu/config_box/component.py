from aether_gui.utils.ui import StyledComponent
<<<<<<< HEAD
from aether_utils.config import CONFIG_FILE
from PySide6 import QtWidgets

with open(CONFIG_FILE) as f:
            CONTENTS: str = f.read()
=======
from aether_utils.config import get_config
from PySide6 import QtWidgets

CONFIG_FILE = get_config()

CONTENTS: str = CONFIG_FILE.model_dump_json()

>>>>>>> b3c769a (feat(settings_menu): shit appears now lol)

class ConfigBox(StyledComponent):
    def setup(self) -> None:
        self._layout: QtWidgets.QHBoxLayout
        self._container: QtWidgets.QWidget
        self._output_box: QtWidgets.QPlainTextEdit

    def init_ui(self) -> None:
        container = QtWidgets.QWidget(self)
        output_box = QtWidgets.QPlainTextEdit(self)
        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.addWidget(output_box)
        container.setLayout(layout)
        self._container = container
        self._output_box = output_box
        self._layout = layout
        self.set_box_content()

    def set_box_content(self) -> None:
        """Load config file content into box"""
        self._output_box.setPlainText(CONTENTS)


    def get_content(self) -> str:
<<<<<<< HEAD
          return CONTENTS
=======
        extracted = self._output_box.toPlainText()
        return extracted
>>>>>>> b3c769a (feat(settings_menu): shit appears now lol)
