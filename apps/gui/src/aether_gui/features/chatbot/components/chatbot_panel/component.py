from pathlib import Path

from aether_gui.utils.ui import StyledComponent
from PySide6 import QtCore, QtWidgets


class ChatbotPanel(StyledComponent):
    """Container that owns the chat layout and background styling."""

    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        """Initialize panel state and let StyledComponent build the UI."""
        self._layout: QtWidgets.QVBoxLayout | None = None
        self._body: QtWidgets.QWidget | None = None
        super().__init__(parent)

    def init_ui(self) -> None:
        """Build the panel layout and enable themed background painting."""
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        self._layout = layout

    def set_body(self, body: QtWidgets.QWidget) -> None:
        """Swap the panel body widget (e.g., a chat history view)."""
        if self._layout is None:
            return
        if self._body is not None:
            self._layout.removeWidget(self._body)
            self._body.setParent(None)
        self._body = body
        self._layout.addWidget(body)
        self._layout.setStretchFactor(body, 1)

    def style_file(self) -> Path | None:
        """Return the QSS template that paints the panel background."""
        return Path(__file__).resolve().parent / "styles.qss.jinja"
