# theme_manager.py
from aether_utils.logger import get_logger
from PySide6 import QtWidgets
from PySide6.QtCore import QEvent, QObject, Signal
from PySide6.QtGui import QFont

logger = get_logger("theme_manager")


class FontManager(QObject):
    """
    Manages light/dark themes for the entire application by installing a
    global event filter on QApplication. Detects theme changes by monitoring
    QEvent.PaletteChange events.
    """

    font_change_event = Signal(QFont)

    def __init__(self, window: QtWidgets.QWidget):
        """Initialize the font manager and read the current font."""
        super().__init__()
        self._installed = False
        self._window = window
        self.current_font: QFont = self.detect_font()

    def eventFilter(self, obj, event) -> bool:
        """Handle palette changes and emit theme updates.

        Args:
            obj: Qt object emitting the event.
            event: Qt event being filtered.

        Returns:
            True if the event is handled, otherwise False.
        """

        if event.type() != QEvent.Type.FontChange:
            return False

        if self._window is None:
            return False

        # Only react if the event landed on our window itself.
        # (Descendants also receive FontChange when the window's font changes,
        # but reading win.font() once per real change is what we want.)
        if obj is not self._window:
            return False

        new_font = self._window.font()

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

    def detect_font(self) -> QFont:
        """Detect the current font from the active palette.

        Returns:
            FontInfo containing the current font styles
        """

        if self._window is not None:
            return self._window.font()

        # Fallback to application default font if window reference is missing
        return self._get_app().font()

    def get_current_font(self) -> QFont:
        """Return the current font snapshot.

        Returns:
            QFont
        """
        return self.current_font
