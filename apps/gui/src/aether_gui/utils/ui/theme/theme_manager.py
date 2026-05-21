# theme_manager.py
from aether_utils.logger import get_logger
from PySide6.QtCore import QEvent, QObject, Signal
from PySide6.QtGui import QPalette
from PySide6.QtWidgets import QApplication

from .types import Theme, ThemeColors

logger = get_logger("theme_manager")


class ThemeManager(QObject):
    theme_changed = Signal(ThemeColors, str)
    """
    Manages light/dark themes for the entire application by installing a
    global event filter on QApplication. Detects theme changes by monitoring
    QEvent.PaletteChange events.
    """

    def __init__(self):
        super().__init__()
        self._installed = False
        self.current_mode: Theme = self.detect_mode()
        self.theme_colors: ThemeColors = self._read_palette()  # read only, no emit yet

    def _get_app(self) -> QApplication:
        app = QApplication.instance()
        if app is None:
            raise RuntimeError("No QApplication instance found")
        assert isinstance(app, QApplication)
        return app

    def eventFilter(self, obj, event) -> bool:
        if event.type() != QEvent.Type.PaletteChange:
            return False

        new_mode = self.detect_mode()
        if self.current_mode == new_mode:
            return False

        logger.info("Theme changed to: %s", new_mode)
        self.current_mode = new_mode
        self.theme_colors = self._read_palette()
        self.theme_changed.emit(self.theme_colors, self.current_mode)

        return False

    def install_event_filter(self):
        if self._installed:
            return
        self._get_app().installEventFilter(self)
        self._installed = True

    def detect_mode(self) -> Theme:
        try:
            app = self._get_app()
            window = app.activeWindow() or app.focusWidget()
            palette = window.palette() if window else app.palette()
            return "dark" if palette.color(QPalette.ColorRole.Text).lightness() > 128 else "light"
        except Exception as e:
            logger.warning("Failed to detect theme, defaulting to light: %s", e)
            return "light"

    def _read_palette(self) -> ThemeColors:
        """Read current palette colors without emitting any signal."""
        app = self._get_app()
        window = app.activeWindow() or app.focusWidget()
        palette = window.palette() if window else app.palette()

        def color(role: QPalette.ColorRole) -> str:
            return palette.color(role).name()

        return {
            "window": color(QPalette.ColorRole.Window),
            "base": color(QPalette.ColorRole.Base),
            "text": color(QPalette.ColorRole.Text),
            "mid": color(QPalette.ColorRole.Mid),
            "button": color(QPalette.ColorRole.Button),
            "highlight": color(QPalette.ColorRole.Highlight),
        }

    def current_theme(self) -> tuple[ThemeColors, Theme]:
        """Snapshot of the current theme — useful for initial paint."""
        return self.theme_colors, self.current_mode
