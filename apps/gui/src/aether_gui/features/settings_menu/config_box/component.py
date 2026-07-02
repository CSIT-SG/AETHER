import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from aether_gui.utils.ui import StyledComponent
from aether_utils.config import get_config
from PySide6 import QtCore, QtWidgets

from .form_builder import SettingsForm, build_settings_form


class ConfigBox(StyledComponent):
    """Schema-driven, VSCode-style editor for the AETHER config.

    Provides two interchangeable views of the same config:

    * a searchable, categorized **form** (sidebar + scrollable controls), and
    * a raw **JSON** editor.

    The ``{ } JSON`` button opens the JSON view; the ``Settings`` button returns
    to the form. Either view serializes back to JSON via :meth:`get_content`,
    preserving the contract used by the Apply/Ok buttons.
    """
    def setup(self) -> None:
        self._form: SettingsForm | None = None
        self._getter: Callable[[], dict[str, Any]] | None = None
        self._sections: dict[str, QtWidgets.QWidget] = {}
        self._baseline: str | None = None
        self._stack: QtWidgets.QStackedWidget
        self._form_page: QtWidgets.QWidget
        self._json_page: QtWidgets.QPlainTextEdit
        self._search: QtWidgets.QLineEdit
        self._results: QtWidgets.QLabel
        self._json_btn: QtWidgets.QPushButton
        self._back_btn: QtWidgets.QPushButton
        self._nav: QtWidgets.QListWidget
        self._scroll: QtWidgets.QScrollArea

    def init_ui(self) -> None:
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addLayout(self._build_header())
        layout.addWidget(self._build_stack())
        self.setLayout(layout)

        self._update_chrome(json_mode=False)
        self._install_form(get_config().model_dump())
        self._reset_baseline()

    def style_file(self) -> Path | None:
        return Path(__file__).with_name("styles.qss.jinja")

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_header(self) -> QtWidgets.QHBoxLayout:
        """Header row: back button, search, results count and JSON button."""
        self._back_btn = self._make_nav_button(
            "← Settings", "JsonBack", "Return to the settings form", self._show_form
        )
        self._json_btn = self._make_nav_button(
            "{ } JSON", "JsonToggle", "View and edit the raw settings JSON", self._show_json
        )

        self._search = QtWidgets.QLineEdit(self)
        self._search.setObjectName("SettingsSearch")
        self._search.setPlaceholderText("Search settings")
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(self._apply_filter)

        self._results = QtWidgets.QLabel("", self)
        self._results.setObjectName("SettingsCount")

        header = QtWidgets.QHBoxLayout()
        header.setContentsMargins(2, 2, 2, 2)
        header.addWidget(self._back_btn)
        header.addWidget(self._search, 1)
        header.addWidget(self._results)
        header.addWidget(self._json_btn)
        return header

    def _make_nav_button(
        self, text: str, object_name: str, tooltip: str, on_click: Callable[[], None]
    ) -> QtWidgets.QPushButton:
        button = QtWidgets.QPushButton(text, self)
        button.setObjectName(object_name)
        button.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
        button.setToolTip(tooltip)
        button.clicked.connect(on_click)
        return button

    def _build_stack(self) -> QtWidgets.QStackedWidget:
        """Stacked widget holding the form page and the raw JSON page."""
        self._form_page = self._build_form_page()

        self._json_page = QtWidgets.QPlainTextEdit(self)
        self._json_page.setObjectName("SettingsJson")
        self._json_page.textChanged.connect(self._refresh_dirty)

        stack = QtWidgets.QStackedWidget(self)
        stack.addWidget(self._form_page)
        stack.addWidget(self._json_page)
        self._stack = stack
        return stack

    def _build_form_page(self) -> QtWidgets.QWidget:
        """Form page: category navigation sidebar beside the scrollable form."""
        self._nav = QtWidgets.QListWidget(self)
        self._nav.setObjectName("SettingsNav")
        self._nav.setMinimumWidth(150)
        self._nav.setMaximumWidth(200)
        self._nav.setSpacing(2)
        self._nav.setUniformItemSizes(True)
        self._nav.setWordWrap(False)
        self._nav.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._nav.itemClicked.connect(self._on_nav_clicked)

        self._scroll = QtWidgets.QScrollArea(self)
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)

        page = QtWidgets.QWidget(self)
        body = QtWidgets.QHBoxLayout(page)
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(8)
        body.addWidget(self._nav)
        body.addWidget(self._scroll, 1)
        return page

    def _install_form(self, data: dict[str, Any]) -> None:
        """Build the form from ``data`` and mount it into the nav + scroll area."""
        form = build_settings_form(type(get_config()), data)
        self._form = form
        self._getter = form.getter
        self._sections: dict[str, QtWidgets.QWidget] = dict(form.sections)

        for _text, widget, _category in form.rows:
            widget.changed.connect(self._refresh_dirty)

        self._scroll.setWidget(form.widget)
        self._nav.clear()
        self._nav.addItems([title for title, _ in form.sections])
        if self._nav.count():
            self._nav.setCurrentRow(0)
        self._apply_filter(self._search.text())

    # ------------------------------------------------------------------
    # navigation + search
    # ------------------------------------------------------------------
    def _on_nav_clicked(self, item: QtWidgets.QListWidgetItem) -> None:
        """Scroll the form so the clicked category sits at the top of the viewport."""
        section = self._sections.get(item.text())
        content = self._scroll.widget()
        if section is None or content is None:
            return
        # Map the section's top into the scroll content and jump the scrollbar
        # there, so the category is top-aligned rather than merely made visible.
        top = section.mapTo(content, QtCore.QPoint(0, 0)).y()
        scrollbar = self._scroll.verticalScrollBar()
        scrollbar.setValue(min(top, scrollbar.maximum()))

    def _apply_filter(self, text: str) -> None:
        """Show only fields/categories matching the search query and update the count."""
        if self._form is None:
            return
        query = text.strip().lower()
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

        for row in range(self._nav.count()):
            nav_item = self._nav.item(row)
            nav_item.setHidden(bool(query) and nav_item.text() not in visible_categories)

        total = len(self._form.rows)
        self._results.setText(
            f"{visible_count} of {total} settings" if query else f"{total} settings"
        )

    # ------------------------------------------------------------------
    # form <-> JSON view switching
    # ------------------------------------------------------------------
    def _show_json(self) -> None:
        """Enter the raw JSON view, seeded from the form's current values."""
        if self._getter is not None:
            self._json_page.setPlainText(json.dumps(self._getter(), indent=2))
        self._stack.setCurrentWidget(self._json_page)
        self._update_chrome(json_mode=True)

    def _show_form(self) -> None:
        """Return to the form view, rebuilding it from the edited JSON.

        Stays in the JSON view if the text is not a valid JSON object, so the
        user never loses their edits to a parse error.
        """
        parsed = self._parse_json_editor()
        if parsed is None:
            self.logger.warning("Cannot return to form view: settings JSON is invalid.")
            return
        self._install_form(parsed)
        self._stack.setCurrentWidget(self._form_page)
        self._update_chrome(json_mode=False)
        self._refresh_dirty()

    def _parse_json_editor(self) -> dict[str, Any] | None:
        """Parse the JSON editor, returning a dict or ``None`` if invalid."""
        try:
            parsed = json.loads(self._json_page.toPlainText())
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None

    def _update_chrome(self, *, json_mode: bool) -> None:
        """Toggle which header controls are visible for the active view."""
        self._search.setVisible(not json_mode)
        self._results.setVisible(not json_mode)
        self._json_btn.setVisible(not json_mode)
        self._back_btn.setVisible(json_mode)

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
        return json.dumps(data, sort_keys=True) if isinstance(data, dict) else None

    def is_dirty(self) -> bool:
        """Whether the current content differs from the last saved state."""
        current = self._canonical()
        if current is None:
            # Not parseable JSON counts as dirty so Apply stays actionable.
            return True
        return current != self._baseline

    # Emitted with the current "has unsaved edits" state whenever it may change.
    dirtyChanged = QtCore.Signal(bool)

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
            return self._json_page.toPlainText()
        if self._getter is None:
            return "{}"
        return json.dumps(self._getter(), indent=2)
