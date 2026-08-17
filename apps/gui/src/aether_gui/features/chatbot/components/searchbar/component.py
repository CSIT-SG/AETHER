from pathlib import Path
from typing import Any, cast

from aether_gui.utils.ui import FontPlugin, StyledComponent
from PySide6.QtCore import QEvent, QObject, Qt, Signal
from PySide6.QtGui import QFont, QKeyEvent
from PySide6.QtWidgets import QHBoxLayout, QLabel, QLineEdit, QPushButton


class SearchBar(StyledComponent):  # type: ignore[misc]
    """Ctrl+F search bar for finding text across the conversation."""

    search_changed = Signal(str)
    next_requested = Signal()
    prev_requested = Signal()
    closed = Signal()

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent, plugins=[FontPlugin()])

    def setup(self) -> None:
        self._input: QLineEdit | None = None
        self._count_label: QLabel | None = None
        self._prev_btn: QPushButton | None = None
        self._next_btn: QPushButton | None = None
        self._close_btn: QPushButton | None = None

    def init_ui(self) -> None:
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 1)
        layout.setSpacing(4)

        search_input = QLineEdit(self)
        search_input.setObjectName("SearchInput")
        search_input.setPlaceholderText("Find in conversation…")
        search_input.textChanged.connect(self.search_changed.emit)
        search_input.installEventFilter(self)

        count_label = QLabel("0/0", self)
        count_label.setObjectName("SearchCount")

        prev_btn = QPushButton("↑", self)
        prev_btn.setObjectName("SearchPrevButton")
        prev_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        prev_btn.clicked.connect(self.prev_requested.emit)

        next_btn = QPushButton("↓", self)
        next_btn.setObjectName("SearchNextButton")
        next_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        next_btn.clicked.connect(self.next_requested.emit)

        close_btn = QPushButton("✕", self)
        close_btn.setObjectName("SearchCloseButton")
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.clicked.connect(self.closed.emit)

        layout.addWidget(search_input, 1)
        layout.addWidget(count_label)
        layout.addWidget(prev_btn)
        layout.addWidget(next_btn)
        layout.addWidget(close_btn)

        self._input = search_input
        self._count_label = count_label
        self._prev_btn = prev_btn
        self._next_btn = next_btn
        self._close_btn = close_btn

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:
        if (
            obj is self._input
            and isinstance(event, QKeyEvent)
            and event.type() == QKeyEvent.Type.KeyPress
        ):
            if event.key() == Qt.Key.Key_Escape:
                self.closed.emit()
                return True
            if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                if event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
                    self.prev_requested.emit()
                else:
                    self.next_requested.emit()
                return True
        return super().eventFilter(obj, event)

    def focus_input(self) -> None:
        if self._input:
            self._input.setFocus()
            self._input.selectAll()

    def clear_input(self) -> None:
        if self._input:
            self._input.clear()

    def update_count(self, current: int, total: int) -> None:
        if self._count_label:
            self._count_label.setText(f"{current}/{total}")

    def style_file(self) -> Path | None:
        return Path(__file__).resolve().parent / "styles.qss.jinja"

    def on_font_change(self, font: QFont) -> None:
        for widget in (
            self._input,
            self._count_label,
            self._prev_btn,
            self._next_btn,
            self._close_btn,
        ):
            if widget is not None:
                widget.setFont(font)

    def _current_font(self) -> QFont:
        return cast(QFont, self.get_plugin(FontPlugin).current_font)
