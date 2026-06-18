from aether_utils.config import get_config
from aether_utils.logger import get_logger
from PySide6 import QtWidgets

from .config_box import ConfigBox
from .config_buttons import ButtonRow

CONTENTS = get_config().model_dump()

logger = get_logger("test_setting_menu")


class SettingsMenuHandler(QtWidgets.QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Aether")
        self.resize(600, 350)
        self._layout: QtWidgets.QVBoxLayout
        self._buttons: ButtonRow
        self._config_box: ConfigBox
        self._cfg_message: QtWidgets.QLabel
        self.init_ui()

    def init_ui(self) -> None:
        layout = QtWidgets.QVBoxLayout(self)
        config_box = ConfigBox(self)
        text_label = QtWidgets.QLabel("", self)
        text_label.setContentsMargins(8, 0, 8, 0)
        buttons: ButtonRow = ButtonRow(
            config_box.get_content,
            self.close,
            self.show_error_message,
            self.clear_message_box,
            self.set_config_message,
            parent=self,
        )
        config_box.setMinimumWidth(500)
        config_box.setMinimumHeight(200)
        self._layout = layout
        self._config_box = config_box
        self._buttons = buttons
        self._cfg_message = text_label
        self._layout.addWidget(self._config_box)
        self._layout.addWidget(self._cfg_message)
        self._layout.addWidget(self._buttons)
        self.setLayout(self._layout)

    def show_error_message(self) -> None:
        self._cfg_message.setText("Invalid config, check IDA output for more details")
        self._cfg_message.setStyleSheet("color: red")

    def clear_message_box(self) -> None:
        self._cfg_message.setText(" ")

    def set_config_message(self) -> None:
        self._cfg_message.setText("Config successfully applied!")
        self._cfg_message.setStyleSheet("color: green")
