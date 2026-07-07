from collections.abc import Callable
from pathlib import Path

from aether_gui.features.settings_menu.style_contracts import (
    JSON_BACK_OBJECT_NAME,
    JSON_TOGGLE_OBJECT_NAME,
    SETTINGS_COUNT_OBJECT_NAME,
    SETTINGS_SEARCH_OBJECT_NAME,
)
from aether_gui.utils.ui import FontPlugin, StyledComponent
from PySide6 import QtCore, QtWidgets
from PySide6.QtGui import QFont


class SearchBar(StyledComponent):
    """Header row of the settings editor.

    Holds the settings search box, the results count and the view-switching
    buttons. Emits signals only; the owning ConfigBox decides what the clicks
    and queries mean.
    """

    search_changed = QtCore.Signal(str)
    json_clicked = QtCore.Signal()
    back_clicked = QtCore.Signal()

    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent, plugins=[FontPlugin()])

    def setup(self) -> None:
        self._search: QtWidgets.QLineEdit
        self._results: QtWidgets.QLabel
        self._json_btn: QtWidgets.QPushButton
        self._back_btn: QtWidgets.QPushButton

    def init_ui(self) -> None:
        self._back_btn = self._make_button(
            "Back to Settings",
            JSON_BACK_OBJECT_NAME,
            "Return to the settings form",
            self.back_clicked.emit,
        )
        self._json_btn = self._make_button(
            "{ } JSON",
            JSON_TOGGLE_OBJECT_NAME,
            "View and edit the raw settings JSON",
            self.json_clicked.emit,
        )

        self._search = QtWidgets.QLineEdit(self)
        self._search.setObjectName(SETTINGS_SEARCH_OBJECT_NAME)
        self._search.setPlaceholderText("Search settings")
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(self.search_changed)

        self._results = QtWidgets.QLabel("", self)
        self._results.setObjectName(SETTINGS_COUNT_OBJECT_NAME)

        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.addWidget(self._back_btn)
        layout.addWidget(self._search, 1)
        layout.addWidget(self._results)
        layout.addWidget(self._json_btn)
        self.setLayout(layout)

        self.set_json_mode(False)

    def style_file(self) -> Path | None:
        return Path(__file__).with_name("styles.qss.jinja")

    def _make_button(
        self, text: str, object_name: str, tooltip: str, on_click: Callable[[], None]
    ) -> QtWidgets.QPushButton:
        button = QtWidgets.QPushButton(text, self)
        button.setObjectName(object_name)
        button.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
        button.setToolTip(tooltip)
        button.clicked.connect(on_click)
        return button

    def text(self) -> str:
        """Return the current search query."""
        return self._search.text()

    def set_counts(self, visible: int, total: int, *, filtering: bool) -> None:
        """Update the results count label next to the search box."""
        text = (
            f"{visible} of {total} settings"
            if filtering
            else f"{total} settings"
        )
        self._results.setText(text)

    def set_json_mode(self, json_mode: bool) -> None:
        """Swap which controls are shown: search chrome (form) vs back button (JSON)."""
        self._search.setVisible(not json_mode)
        self._results.setVisible(not json_mode)
        self._json_btn.setVisible(not json_mode)
        self._back_btn.setVisible(json_mode)

    def on_font_change(self, font: QFont) -> None:
        pass

    def _current_font(self) -> QFont:
        return self.get_plugin(FontPlugin).current_font


def create_search_bar(parent: QtWidgets.QWidget | None = None) -> SearchBar:
    return SearchBar(parent=parent)
