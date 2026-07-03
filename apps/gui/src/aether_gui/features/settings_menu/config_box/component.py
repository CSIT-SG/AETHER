import json
from typing import Any

from aether_gui.utils.ui import StyledComponent
from aether_utils.config import get_config
from PySide6 import QtCore, QtWidgets

from ..constants import (
    CONFIG_BOX_SPACING,
    INVALID_JSON_RETURN_WARNING,
    JSON_INDENT,
    JSON_SORT_KEYS,
    NO_MARGINS,
)
from .json_editor import JsonEditor
from .search_bar import SearchBar
from .settings_form_view import SettingsFormView


class ConfigBox(StyledComponent):
    """Schema-driven, VSCode-style editor for the AETHER config.

    Coordinates :class:`SearchBar`, :class:`SettingsFormView` and
    :class:`JsonEditor`. Owns the cross-cutting state: form/JSON view switching,
    dirty tracking and the :meth:`get_content` contract used by the Apply/Ok
    buttons.
    """

    # Emitted with the current "has unsaved edits" state whenever it may change.
    dirtyChanged = QtCore.Signal(bool)

    def setup(self) -> None:
        # Canonical JSON of the last saved state; None until the form is loaded.
        self._baseline: str | None = None
        self._search_bar: SearchBar
        self._json_page: JsonEditor
        self._form_view: SettingsFormView
        self._stack: QtWidgets.QStackedWidget

    def init_ui(self) -> None:
        self._search_bar = SearchBar(self)
        self._form_view = SettingsFormView(self)
        self._json_page = JsonEditor(self)

        self._stack = QtWidgets.QStackedWidget(self)
        self._stack.addWidget(self._form_view)
        self._stack.addWidget(self._json_page)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(*NO_MARGINS)
        layout.setSpacing(CONFIG_BOX_SPACING)
        layout.addWidget(self._search_bar)
        layout.addWidget(self._stack)
        self.setLayout(layout)

        self._connect_signals()
        self._install_form(get_config().model_dump())
        # The freshly loaded form is, by definition, the saved state.
        self._reset_baseline()

    def _connect_signals(self) -> None:
        self._search_bar.search_changed.connect(self._apply_filter)
        self._search_bar.json_clicked.connect(self._show_json)
        self._search_bar.back_clicked.connect(self._show_form)
        self._form_view.changed.connect(self._refresh_dirty)
        self._json_page.changed.connect(self._refresh_dirty)

    # ------------------------------------------------------------------
    # form loading + search
    # ------------------------------------------------------------------
    def _install_form(self, data: dict[str, Any]) -> None:
        """Build the form from ``data`` and refresh the sidebar and filter."""
        self._form_view.install(type(get_config()), data)
        self._apply_filter(self._search_bar.text())

    def _apply_filter(self, text: str) -> None:
        """Filter the form and reflect the result in the sidebar and count label."""
        visible, total, visible_categories = self._form_view.apply_filter(text)
        self._search_bar.set_counts(visible, total, filtering=visible_categories is not None)

    # ------------------------------------------------------------------
    # form <-> JSON view switching
    # ------------------------------------------------------------------
    def _show_json(self) -> None:
        """Enter the raw JSON view, seeded from the form's current values."""
        self._json_page.set_values(self._form_view.values())
        self._stack.setCurrentWidget(self._json_page)
        self._search_bar.set_json_mode(True)

    def _show_form(self) -> None:
        """Return to the form view, rebuilding it from the edited JSON.

        Stays in the JSON view if the text is not a valid JSON object, so the
        user never loses their edits to a parse error.
        """
        parsed = self._json_page.parse()
        if parsed is None:
            self.logger.warning(INVALID_JSON_RETURN_WARNING)
            return
        self._install_form(parsed)
        self._stack.setCurrentWidget(self._form_view)
        self._search_bar.set_json_mode(False)
        self._refresh_dirty()

    def _in_json_mode(self) -> bool:
        return self._stack.currentWidget() is self._json_page

    # ------------------------------------------------------------------
    # dirty tracking (drives the Apply button)
    # ------------------------------------------------------------------
    def _canonical(self) -> str | None:
        """Order-independent JSON of the current content, or ``None`` if invalid."""
        try:
            data = json.loads(self.get_content())
        except json.JSONDecodeError:
            return None
        return json.dumps(data, sort_keys=JSON_SORT_KEYS) if isinstance(data, dict) else None

    def is_dirty(self) -> bool:
        """Whether the current content differs from the last saved state."""
        current = self._canonical()
        if current is None:
            # Unparseable JSON counts as dirty so Apply stays actionable.
            return True
        return current != self._baseline

    def _refresh_dirty(self) -> None:
        self.dirtyChanged.emit(self.is_dirty())

    def _reset_baseline(self) -> None:
        """Adopt the current content as the saved baseline (no unsaved edits)."""
        self._baseline = self._canonical()
        self.dirtyChanged.emit(False)

    def mark_saved(self) -> None:
        """Called after the config is written so the form is no longer dirty."""
        self._reset_baseline()

    # ------------------------------------------------------------------
    # output
    # ------------------------------------------------------------------
    def get_content(self) -> str:
        """Return the active view's current values as a JSON string."""
        if self._in_json_mode():
            return self._json_page.text()
        return json.dumps(self._form_view.values(), indent=JSON_INDENT)


def create_config_box(parent: QtWidgets.QWidget | None = None) -> ConfigBox:
    return ConfigBox(parent=parent)
