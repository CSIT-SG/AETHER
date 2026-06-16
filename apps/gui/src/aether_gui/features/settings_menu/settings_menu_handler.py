<<<<<<< HEAD
=======
from aether_utils.config import get_config
>>>>>>> b3c769a (feat(settings_menu): shit appears now lol)
from aether_utils.logger import get_logger
from config_box import ConfigBox
from config_buttons import ButtonRow
from PySide6 import QtWidgets

<<<<<<< HEAD
logger = get_logger("settings_menu_plugin")

class SettingsMenuHandler(QtWidgets.QDialog):
    def __init__(self, parent = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("My Dialog")
        self.resize(400, 300)
        self._layout: QtWidgets.QVBoxLayout


    def init_ui(self) -> None:
        config_box = ConfigBox()
        config_box.set_box_content()
        layout = QtWidgets.QVBoxLayout(self)
        buttons: ButtonRow = ButtonRow()
        buttons.set_buttons(get_content=config_box.get_content,
                            on_close=self.close)
        self._layout = layout

=======
from .config_box import ConfigBox
from .config_buttons import ButtonRow

CONTENTS = get_config().model_dump()
ACTION_NAME = "aether:open_settings"
ACTION_LABEL = "Aether Settings"

logger = get_logger("test_setting_menu")


class SettingsMenuHandler(QtWidgets.QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Aether_Config")
        self.resize(600, 300)
        self._layout: QtWidgets.QVBoxLayout
        self._buttons: ButtonRow
        self._config_box: ConfigBox
        self._test: QtWidgets.QPlainTextEdit
        self.init_ui()

    def init_ui(self) -> None:
        print("init ui")
        layout = QtWidgets.QVBoxLayout(self)
        config_box = ConfigBox(self)
        buttons: ButtonRow = ButtonRow(self)
        buttons.set_buttons(get_content=CONTENTS, on_close=self.close)
        self._layout = layout
        self._config_box = config_box
        self._buttons = buttons
        self._layout.addWidget(self._config_box)
        self._layout.addWidget(self._buttons)
        self.setLayout(self._layout)
>>>>>>> b3c769a (feat(settings_menu): shit appears now lol)
