from pathlib import Path
from typing import Any

from aether_gui.utils.ui import FontPlugin, StyledComponent
from pydantic import BaseModel
from PySide6 import QtCore, QtWidgets
from PySide6.QtGui import QFont

from .form_builder import FilterResult, SettingsForm, build_settings_form


class ConfigForm(StyledComponent):
    """The main config view: a scrollable, categorized settings form.

    Hosts the widget tree produced by :func:`build_settings_form` and owns the
    field-level concerns: collecting values, live search filtering and
    scrolling to a category. Emits :attr:`changed` whenever any field edits.
    """

    changed = QtCore.Signal()

    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent, plugins=[FontPlugin()])

    def setup(self) -> None:
        self._form: SettingsForm | None = None
        self._sections: dict[str, QtWidgets.QWidget] = {}
        self._scroll: QtWidgets.QScrollArea

    def init_ui(self) -> None:
        scroll = QtWidgets.QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(scroll)
        self._scroll = scroll
        self.setLayout(layout)

    def style_file(self) -> Path | None:
        return Path(__file__).with_name("styles.qss.jinja")

    def on_font_change(self, font: QFont) -> None:
        pass

    def _current_font(self) -> QFont:
        return self.get_plugin(FontPlugin).current_font

    def install(self, model_cls: type[BaseModel], data: dict[str, Any]) -> list[str]:
        """Build the form from ``data`` and mount it, returning the category titles."""
        form = build_settings_form(model_cls, data)
        self._form = form
        self._sections = {section["title"]: section["widget"] for section in form.sections}

        for row in form.rows:
            row.widget.changed.connect(self.changed)

        self._scroll.setWidget(form.widget)
        return [section["title"] for section in form.sections]

    def values(self) -> dict[str, Any]:
        """Collect the current control values into a nested dict."""
        return self._form.getter() if self._form is not None else {}

    def has_required_missing(self) -> bool:
        """Whether the form has any required fields left empty."""
        return self._form.has_required_missing() if self._form is not None else False

    def scroll_to(self, title: str) -> None:
        """Scroll so the given category sits at the top of the viewport."""
        section = self._sections.get(title)
        content = self._scroll.widget()
        if section is None or content is None:
            return
        # Map the section's top into the scroll content and jump the scrollbar
        # there, so the category is top-aligned rather than merely made visible.
        top = section.mapTo(content, QtCore.QPoint(0, 0)).y()
        scrollbar = self._scroll.verticalScrollBar()
        scrollbar.setValue(min(top, scrollbar.maximum()))

    def apply_filter(self, query: str) -> FilterResult:
        """Show only fields/categories matching ``query``.

        ``categories`` in the result is ``None`` when no filter is active.
        """
        if self._form is None:
            return {"visible": 0, "total": 0, "categories": None}
        query = query.strip().lower()
        visible_categories: set[str] = set()
        visible_count = 0

        for row in self._form.rows:
            match = (not query) or (query in row.search_text)
            row.widget.setVisible(match)
            if match:
                visible_categories.add(row.category)
                visible_count += 1

        for section in self._form.sections:
            section["widget"].setVisible((not query) or (section["title"] in visible_categories))

        return {
            "visible": visible_count,
            "total": len(self._form.rows),
            "categories": visible_categories if query else None,
        }


def create_config_form(parent: QtWidgets.QWidget | None = None) -> ConfigForm:
    return ConfigForm(parent=parent)
