from aether_utils.logger import get_logger
from config_box import ConfigBox
from config_buttons import ButtonRow
from PySide6 import QtWidgets

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

