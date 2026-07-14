from aether_utils.config import get_config, set_config
from aether_utils.get_support import AgentSupport
from aether_utils.json import load_json_object
from aether_utils.logger import get_logger
from PySide6 import QtWidgets

from .api_key_check import run_api_key_check
from .config_box import ConfigBox, create_config_box
from .config_buttons import (
    ApplyButton,
    ButtonRow,
    CancelButton,
    OkButton,
    create_button_row,
)
from .config_message import ConfigMessage, create_config_message

save_logger = get_logger("json_loader")


class SettingsMenuHandler(QtWidgets.QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("AETHER Settings")
        self.resize(900, 600)
        self.setMinimumSize(700, 450)
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
        # Surface coordinator-level failures (e.g. invalid JSON on Back) inline.
        config_box.errorRaised.connect(text_label.show_error)
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
        self._cfg_message.show_error("Invalid config, check IDA output for more details")

    def show_required_fields_message(self) -> None:
        self._cfg_message.show_error("One or more required fields are not filled.")

    def clear_message_box(self) -> None:
        self._cfg_message.clear()

    def apply_config(self) -> None:
        previous_key = get_config().provider.api_key
        if self._save_config():
            self._config_box.mark_saved()
            new_key = get_config().provider.api_key
            if new_key and new_key != previous_key:
                # Validate changed keys without blocking the settings dialog.
                self._cfg_message.show_info("Config applied. Checking API key…")
                run_api_key_check(self._on_api_key_checked)
            else:
                self._cfg_message.show_success("Config applied!")

    def _on_api_key_checked(self, result: AgentSupport) -> None:
        try:
            if result.supported:
                self._cfg_message.show_success("Config applied. API key is valid.")
            else:
                self._cfg_message.show_error(f"Config applied. {result.detail}")
        except RuntimeError:
            pass

    def ok_config(self) -> None:
        if self._save_config():
            self.close()

    def _save_config(self) -> bool:
        self.clear_message_box()
        if self._config_box.has_required_missing():
            self.show_required_fields_message()
            return False
        try:
            formatted = load_json_object(self._config_box.get_content())
            set_config(formatted)
        except Exception as e:
            self.show_error_message()
            # Log the full validation reason; the UI message stays brief.
            save_logger.error("Settings not saved: %s", e)
            return False
        return True
