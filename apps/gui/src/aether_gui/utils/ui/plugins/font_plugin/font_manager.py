# font_manager.py

import ida_kernwin
from aether_utils.logger import get_logger
from PySide6 import QtWidgets
from PySide6.QtCore import QEvent, QObject, Signal
from PySide6.QtGui import QFont

logger = get_logger("font_manager")


class FontManager(QObject):
    """
    Manages font change events from Pseudocode viewer to ensure parity
    """

    font_change_event = Signal(QFont)

    def __init__(self):
        """Initialize the font manager and read the current font."""
        super().__init__()
        self._installed = False
        self.current_font: QFont = self.detect_font()

    def eventFilter(self, obj, event) -> bool:
        """Handle palette changes and emit font updates.

        Args:
            obj: Qt object emitting the event.
            event: Qt event being filtered.

        Returns:
            True if the event is handled, otherwise False.
        """

        if event.type() != QEvent.Type.FontChange:
            return False

        if not isinstance(obj, QtWidgets.QWidget):
            return False

        if self._category_of(obj) != ida_kernwin.BWN_DISASM:
            return False

        new_font = obj.font()
        logger.debug("Font changed to %s %dpt", new_font.family(), new_font.pointSize())
        self.font_change_event.emit(new_font)
        return False

    def _get_app(self) -> QtWidgets.QApplication:
        """Return the active QApplication instance.

        Returns:
            The active QApplication.

        Raises:
            RuntimeError: If no QApplication exists.
        """
        app = QtWidgets.QApplication.instance()
        if app is None:
            raise RuntimeError("No QApplication instance found")
        assert isinstance(app, QtWidgets.QApplication)
        return app

    def install_event_filter(self):
        """Install the global palette change event filter."""

        if self._installed:
            return
        self._get_app().installEventFilter(self)
        self._installed = True

    def _category_of(self, widget: QtWidgets.QWidget) -> int | None:
        w = widget
        while w is not None:
            name = w.objectName()
            if name.startswith("TWidget["):
                title = name.removeprefix("TWidget[").removesuffix("]")
                tw = ida_kernwin.find_widget(title)
                return ida_kernwin.get_widget_type(tw) if tw is not None else None
            w = w.parentWidget()
        return None

    def detect_font(self) -> QFont:
        """Detect the current font from any widget of the watched category.

        Returns:
            QFont of the watched category, or the application default if no
            widget of that category is currently open.
        """
        try:
            app = self._get_app()
            for w in app.allWidgets():
                if not isinstance(w, QtWidgets.QWidget):
                    continue
                if not w.objectName().startswith("TWidget["):
                    continue
                if self._category_of(w) != ida_kernwin.BWN_DISASM:
                    continue
                return QFont(w.font())
            return QFont(app.font())

        except Exception as e:
            logger.warning("Failed to detect font, defaulting to app font: %s", e)
            return QFont(self._get_app().font())

    def get_current_font(self) -> QFont:
        """Return the current font snapshot.

        Returns:
            QFont
        """
        return self.current_font
