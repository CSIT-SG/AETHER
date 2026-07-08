from pathlib import Path

from aether_gui.utils.ui import FontPlugin, StyledComponent
from PySide6 import QtWidgets
from PySide6.QtGui import QFont

from ..styles import MESSAGE_STATE_PROPERTY, MessageState


class ConfigMessage(StyledComponent):
    """Themed status line for the settings dialog.

    Shows error / success / neutral text coloured from the theme's semantic
    ``error`` and ``success`` colours (no hardcoded colours). The active state is
    held in the ``messageState`` dynamic property so the QSS selects the colour;
    it restyles automatically on theme change via the plugin's QSS re-render.
    """

    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent, plugins=[FontPlugin()])

    def setup(self) -> None:
        self._label: QtWidgets.QLabel

    def init_ui(self) -> None:
        label = QtWidgets.QLabel("", self)
        label.setContentsMargins(8, 0, 8, 0)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(label)
        self._label = label
        self.setLayout(layout)
        self._set_state(MessageState.NONE)

    def style_file(self) -> Path | None:
        return Path(__file__).with_name("styles.qss.jinja")

    def on_font_change(self, font: QFont) -> None:
        pass

    def _current_font(self) -> QFont:
        return self.get_plugin(FontPlugin).current_font

    def show_error(self, text: str) -> None:
        """Display an error message in the theme's error colour."""
        self._label.setText(text)
        self._set_state(MessageState.ERROR)

    def show_success(self, text: str) -> None:
        """Display a success message in the theme's success colour."""
        self._label.setText(text)
        self._set_state(MessageState.SUCCESS)

    def clear(self) -> None:
        """Clear the message and reset to neutral styling."""
        self._label.setText(" ")
        self._set_state(MessageState.NONE)

    def _set_state(self, state: MessageState) -> None:
        """Set the label's state property and re-polish so the QSS re-evaluates."""
        self._label.setProperty(MESSAGE_STATE_PROPERTY, state.value)
        style = self._label.style()
        style.unpolish(self._label)
        style.polish(self._label)


def create_config_message(parent: QtWidgets.QWidget | None = None) -> ConfigMessage:
    return ConfigMessage(parent=parent)
