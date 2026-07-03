from typing import Any

from aether_gui.utils.ui import StyledComponent
from pydantic import BaseModel
from PySide6 import QtCore, QtWidgets

from ..config_form import ConfigForm
from ..sidebar import Sidebar


class SettingsFormView(StyledComponent):
    """Settings form view: category sidebar plus scrollable config form."""

    changed = QtCore.Signal()

    def setup(self) -> None:
        self._sidebar: Sidebar
        self._config_form: ConfigForm

    def init_ui(self) -> None:
        self._sidebar = Sidebar(self)
        self._config_form = ConfigForm(self)

        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(self._sidebar)
        layout.addWidget(self._config_form, 1)
        self.setLayout(layout)

        self._sidebar.category_clicked.connect(self._config_form.scroll_to)
        self._config_form.changed.connect(self.changed.emit)

    def install(self, model_cls: type[BaseModel], data: dict[str, Any]) -> None:
        """Build the form from ``data`` and refresh the sidebar."""
        categories = self._config_form.install(model_cls, data)
        self._sidebar.set_categories(categories)

    def values(self) -> dict[str, Any]:
        """Return the form's current settings values."""
        return self._config_form.values()

    def apply_filter(self, text: str) -> tuple[int, int, set[str] | None]:
        """Filter fields and mirror the category visibility in the sidebar."""
        visible, total, visible_categories = self._config_form.apply_filter(text)
        self._sidebar.set_visible_categories(visible_categories)
        return visible, total, visible_categories


def create_settings_form_view(parent: QtWidgets.QWidget | None = None) -> SettingsFormView:
    return SettingsFormView(parent=parent)
