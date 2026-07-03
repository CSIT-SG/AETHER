from aether_utils.logger import get_logger
from PySide6 import QtWidgets

from .config_box import ConfigBox, create_config_box
from .config_buttons import ButtonRow, create_button_row
from .config_message import ConfigMessage, create_config_message
from .constants import SETTINGS_MENU_LOGGER

SETTINGS_DIALOG_TITLE = "AETHER Settings"
SETTINGS_DIALOG_INITIAL_SIZE = (900, 600)
SETTINGS_DIALOG_MINIMUM_SIZE = (700, 450)
CONFIG_BOX_MINIMUM_SIZE = (500, 200)
INVALID_CONFIG_MESSAGE = "Invalid config, check IDA output for more details"
CONFIG_APPLIED_MESSAGE = "Config applied!"

logger = get_logger(SETTINGS_MENU_LOGGER)


class SettingsMenuHandler(QtWidgets.QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(SETTINGS_DIALOG_TITLE)
        self.resize(*SETTINGS_DIALOG_INITIAL_SIZE)
        self.setMinimumSize(*SETTINGS_DIALOG_MINIMUM_SIZE)
        self._layout: QtWidgets.QVBoxLayout
        self._buttons: ButtonRow
        self._config_box: ConfigBox
        self._cfg_message: ConfigMessage
        self.init_ui()

    def init_ui(self) -> None:
        layout = QtWidgets.QVBoxLayout(self)
        config_box = create_config_box(self)
        text_label = create_config_message(self)
        buttons: ButtonRow = create_button_row(
            config_box.get_content,
            self.close,
            self.show_error_message,
            self.clear_message_box,
            self.on_success,
            parent=self,
        )
        # Apply is actionable only while the form has unsaved edits.
        buttons.apply_button.setEnabled(config_box.is_dirty())
        config_box.dirtyChanged.connect(buttons.apply_button.setEnabled)
        config_box.setMinimumWidth(CONFIG_BOX_MINIMUM_SIZE[0])
        config_box.setMinimumHeight(CONFIG_BOX_MINIMUM_SIZE[1])
        self._layout = layout
        self._config_box = config_box
        self._buttons = buttons
        self._cfg_message = text_label
        self._layout.addWidget(self._config_box)
        self._layout.addWidget(self._cfg_message)
        self._layout.addWidget(self._buttons)
        self.setLayout(self._layout)

    def show_error_message(self) -> None:
        self._cfg_message.show_error(INVALID_CONFIG_MESSAGE)

    def clear_message_box(self) -> None:
        self._cfg_message.clear()

    def on_success(self) -> None:
        # Runs after a successful Apply: clear the dirty state (which disables the
        # Apply button) and report success without closing the dialog.
        self._config_box.mark_saved()
        self._cfg_message.show_success(CONFIG_APPLIED_MESSAGE)
