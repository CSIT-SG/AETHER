from aether_utils.logger import get_logger
from PySide6 import QtWidgets

from .config_box import ConfigBox
from .config_buttons import ButtonRow
from .config_message import ConfigMessage

logger = get_logger("settings_menu")


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
        config_box = ConfigBox(self)
        text_label = ConfigMessage(self)
        buttons: ButtonRow = ButtonRow(
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

    def clear_message_box(self) -> None:
        self._cfg_message.clear()

    def on_success(self) -> None:
        # Runs after a successful Apply: clear the dirty state (which disables the
        # Apply button) and report success without closing the dialog.
        self._config_box.mark_saved()
        self._cfg_message.show_success("Config applied!")
