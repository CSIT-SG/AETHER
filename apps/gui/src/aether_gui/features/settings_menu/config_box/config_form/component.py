from pathlib import Path
from typing import Any

from aether_gui.utils.ui import StyledComponent
from pydantic import BaseModel
from PySide6 import QtCore, QtWidgets

from .form_builder import SettingsForm, build_settings_form


class ConfigForm(StyledComponent):
    """The main config view: a scrollable, categorized settings form.

    Hosts the widget tree produced by :func:`build_settings_form` and owns the
    field-level concerns: collecting values, live search filtering and
    scrolling to a category. Emits :attr:`changed` whenever any field edits.
    """

    changed = QtCore.Signal()

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

    def install(self, model_cls: type[BaseModel], data: dict[str, Any]) -> list[str]:
        """Build the form from ``data`` and mount it, returning the category titles."""
        form = build_settings_form(model_cls, data)
        self._form = form
        self._sections = dict(form.sections)

        for _text, widget, _category in form.rows:
            widget.changed.connect(self.changed)

        self._scroll.setWidget(form.widget)
        return [title for title, _ in form.sections]

    def values(self) -> dict[str, Any]:
        """Collect the current control values into a nested dict."""
        return self._form.getter() if self._form is not None else {}

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

    def apply_filter(self, query: str) -> tuple[int, int, set[str] | None]:
        """Show only fields/categories matching ``query``.

        Returns:
            ``(visible_count, total, visible_categories)`` where
            ``visible_categories`` is ``None`` when no filter is active.
        """
        if self._form is None:
            return 0, 0, None
        query = query.strip().lower()
        visible_categories: set[str] = set()
        visible_count = 0

        for search_text, widget, category in self._form.rows:
            match = (not query) or (query in search_text)
            widget.setVisible(match)
            if match:
                visible_categories.add(category)
                visible_count += 1

        for title, section in self._form.sections:
            section.setVisible((not query) or (title in visible_categories))

        total = len(self._form.rows)
        return visible_count, total, (visible_categories if query else None)
