from typing import Any

from aether_utils.config import get_config, set_config
from aether_utils.logger import get_logger
from PySide6 import QtWidgets

from .config_box import ConfigBox, create_config_box
from .config_buttons import (
    ApplyButton,
    ButtonRow,
    CancelButton,
    OkButton,
    create_button_row,
)
from .config_message import ConfigMessage, create_config_message
from .json_object import parse_json_object

CONFIG_SAVE_LOGGER = "json_loader"
SETTINGS_DIALOG_TITLE = "AETHER Settings"
SETTINGS_DIALOG_INITIAL_WIDTH = 900
SETTINGS_DIALOG_INITIAL_HEIGHT = 600
SETTINGS_DIALOG_MINIMUM_WIDTH = 700
SETTINGS_DIALOG_MINIMUM_HEIGHT = 450
CONFIG_BOX_MINIMUM_WIDTH = 500
CONFIG_BOX_MINIMUM_HEIGHT = 200
INVALID_CONFIG_MESSAGE = "Invalid config, check IDA output for more details"
CONFIG_APPLIED_MESSAGE = "Config applied!"

save_logger = get_logger(CONFIG_SAVE_LOGGER)


class SettingsMenuHandler(QtWidgets.QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(SETTINGS_DIALOG_TITLE)
        self.resize(SETTINGS_DIALOG_INITIAL_WIDTH, SETTINGS_DIALOG_INITIAL_HEIGHT)
        self.setMinimumSize(SETTINGS_DIALOG_MINIMUM_WIDTH, SETTINGS_DIALOG_MINIMUM_HEIGHT)
        self._layout: QtWidgets.QVBoxLayout
        self._buttons: ButtonRow
        self._config_box: ConfigBox
        self._cfg_message: ConfigMessage
        self.init_ui()

    def init_ui(self) -> None:
        layout = QtWidgets.QVBoxLayout(self)
        config = get_config()
        config_box = create_config_box(type(config), config.model_dump(), self)
        text_label = create_config_message(self)
        ok_button = OkButton(self.ok_config)
        apply_button = ApplyButton(self.apply_config)
        cancel_button = CancelButton(self.close)
        buttons: ButtonRow = create_button_row(
            [ok_button, apply_button, cancel_button],
            parent=self,
        )
        # Apply is actionable only while the form has unsaved edits.
        apply_button.setEnabled(config_box.is_dirty())
        config_box.dirtyChanged.connect(apply_button.setEnabled)
        config_box.setMinimumWidth(CONFIG_BOX_MINIMUM_WIDTH)
        config_box.setMinimumHeight(CONFIG_BOX_MINIMUM_HEIGHT)
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

    def apply_config(self) -> None:
        if self._save_config():
            self.on_success()

    def ok_config(self) -> None:
        if self._save_config():
            self.close()

    def _save_config(self) -> bool:
        self.clear_message_box()
        try:
            formatted = self._parse_config_content()
            set_config(formatted)
        except Exception as e:
            self.show_error_message()
            save_logger.error(e)
            return False
        return True

    def _parse_config_content(self) -> dict[str, Any]:
        formatted = parse_json_object(self._config_box.get_content())
        if formatted is None:
            raise ValueError(INVALID_CONFIG_MESSAGE)
        return formatted

    def on_success(self) -> None:
        # Runs after a successful Apply: clear the dirty state (which disables the
        # Apply button) and report success without closing the dialog.
        self._config_box.mark_saved()
        self._cfg_message.show_success(CONFIG_APPLIED_MESSAGE)
