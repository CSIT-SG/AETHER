from pathlib import Path

from aether_gui.features.settings_menu.constants import SETTINGS_NAV_OBJECT_NAME
from aether_gui.utils.ui import FontPlugin, StyledComponent
from PySide6 import QtCore, QtWidgets
from PySide6.QtGui import QFont


class Sidebar(StyledComponent):
    """Category navigation list on the left of the settings form.

    Shows one entry per settings category; clicking one emits
    :attr:`category_clicked` with the category title. During a search, entries
    whose categories have no matching fields are hidden via
    :meth:`set_visible_categories`.
    """

    category_clicked = QtCore.Signal(str)

    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent, plugins=[FontPlugin()])

    def setup(self) -> None:
        self._list: QtWidgets.QListWidget

    def init_ui(self) -> None:
        nav = QtWidgets.QListWidget(self)
        nav.setObjectName(SETTINGS_NAV_OBJECT_NAME)
        nav.setSpacing(2)
        nav.setUniformItemSizes(True)
        nav.setWordWrap(False)
        nav.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        nav.itemClicked.connect(lambda item: self.category_clicked.emit(item.text()))

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(nav)
        self._list = nav
        self.setLayout(layout)

        self.setMinimumWidth(150)
        self.setMaximumWidth(200)

    def style_file(self) -> Path | None:
        return Path(__file__).with_name("styles.qss.jinja")

    def on_font_change(self, font: QFont) -> None:
        pass

    def _current_font(self) -> QFont:
        return self.get_plugin(FontPlugin).current_font

    def set_categories(self, titles: list[str]) -> None:
        """Replace the category entries and select the first one."""
        self._list.clear()
        self._list.addItems(titles)
        if self._list.count():
            self._list.setCurrentRow(0)

    def set_visible_categories(self, visible: set[str] | None) -> None:
        """Hide entries not in ``visible``; ``None`` shows every entry."""
        for row in range(self._list.count()):
            item = self._list.item(row)
            item.setHidden(visible is not None and item.text() not in visible)


def create_sidebar(parent: QtWidgets.QWidget | None = None) -> Sidebar:
    return Sidebar(parent=parent)
