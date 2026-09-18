from aether_utils.logger import get_logger
from PySide6 import QtWidgets
from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QFont

logger = get_logger("font_manager")


class FontManager(QObject):
    """
    Manages light/dark themes for the entire application by installing a
    global event filter on QApplication. Detects theme changes by monitoring
    QEvent.PaletteChange events.
    """

    font_change_event = Signal(QFont)

    def __init__(self, window_title: str):
        """Initialize the font manager and read the current font."""
        super().__init__()
        self._installed = False
        self._window_title = window_title
        self._suppressed = False
        self.current_font: QFont = self.detect_font()

    def set_font(self, font: QFont) -> None:
        """Update the current font and notify listeners.

        Called by action handlers when the user picks a new font, bumps the
        size, or resets. No-op if the font is unchanged.

        Args:
            font: The new font to apply.
        """
        if self.current_font == font:
            return
        self.current_font = QFont(font)
        self.font_change_event.emit(self.current_font)

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

    def _get_window(self) -> QtWidgets.QWidget | None:
        for w in self._get_app().allWidgets():
            if isinstance(w, QtWidgets.QWidget) and w.windowTitle() == self._window_title:
                return w
        return None

    def detect_font(self) -> QFont:
        """Detect the current font from the active palette.

        Returns:
            FontInfo containing the current font styles
        """

        window = self._get_window()
        if window is not None:
            return QFont(window.font())
        return QFont(self._get_app().font())

    def get_current_font(self) -> QFont:
        """Return the current font snapshot.

        Returns:
            QFont
        """
        return self.current_font
