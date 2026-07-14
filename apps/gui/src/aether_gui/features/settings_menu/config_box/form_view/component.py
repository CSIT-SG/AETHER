from typing import Any

from aether_gui.utils.ui import StyledComponent
from pydantic import BaseModel
from PySide6 import QtCore, QtWidgets

from ..config_form import ConfigForm, FilterResult
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

    def has_required_missing(self) -> bool:
        """Whether any required form field is currently empty."""
        return self._config_form.has_required_missing()

    def set_field_invalid(self, name: str, message: str | None) -> None:
        """Flag (or clear) a field as invalid by name."""
        self._config_form.set_field_invalid(name, message)

    def apply_filter(self, text: str) -> FilterResult:
        """Filter fields and mirror the category visibility in the sidebar."""
        result = self._config_form.apply_filter(text)
        self._sidebar.set_visible_categories(result["categories"])
        return result


def create_settings_form_view(parent: QtWidgets.QWidget | None = None) -> SettingsFormView:
    return SettingsFormView(parent=parent)
