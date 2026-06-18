from aether_utils.config import get_config
from aether_utils.logger import get_logger
from PySide6 import QtWidgets

from .capture_stylesheet import capture_original_stylesheet
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
        self.resize(600, 350)
        self._layout: QtWidgets.QVBoxLayout
        self._buttons: ButtonRow
        self._config_box: ConfigBox
        self._error_message: QtWidgets.QLabel
        self.init_ui()

    def init_ui(self) -> None:
        capture_original_stylesheet(self)
        layout = QtWidgets.QVBoxLayout(self)
        config_box = ConfigBox(self)
        error_label = QtWidgets.QLabel("", self)
        error_label.setStyleSheet("color: red")
        error_label.hide()
        buttons: ButtonRow = ButtonRow(config_box.get_content, self.close, self.show_error, self.clear_error, parent=self)
        config_box.setMinimumWidth(500)
        config_box.setMinimumHeight(200)
        self._layout = layout
        self._config_box = config_box
        self._buttons = buttons
        self._error_message = error_label
        self._layout.addWidget(self._config_box)
        self._layout.addWidget(self._error_message)
        self._layout.addWidget(self._buttons)
        self.setLayout(self._layout)

    def show_error(self) -> None:
        self._error_message.setText("Invalid JSON, check IDA output for more details")
        self._error_message.show()

    def clear_error(self) ->None:
        self._error_message.hide()
