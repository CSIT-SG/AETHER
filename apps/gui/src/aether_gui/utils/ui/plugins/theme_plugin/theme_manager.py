# theme_manager.py
from aether_utils.logger import get_logger
from PySide6.QtCore import QEvent, QObject, Signal
from PySide6.QtGui import QPalette
from PySide6.QtWidgets import QApplication

from .types import Theme, ThemeColors

logger = get_logger("theme_manager")


class ThemeManager(QObject):
    """
    Manages light/dark themes for the entire application by installing a
    global event filter on QApplication. Detects theme changes by monitoring
    QEvent.PaletteChange events.
    """

    theme_change_event = Signal(str, dict)

    def __init__(self):
        super().__init__()
        self._installed = False
        self.current_theme: Theme = self.detect_theme()
        self.theme_colors: ThemeColors = self._read_palette()  # read only, no emit yet

    def eventFilter(self, obj, event) -> bool:
        if event.type() != QEvent.Type.PaletteChange:
            return False

        new_theme = self.detect_theme()
        if self.current_theme == new_theme:
            return False

        logger.info("Theme changed to: %s", new_theme)
        self.current_theme = new_theme
        self.theme_colors = self._read_palette()
        self.theme_change_event.emit(self.current_theme, self.theme_colors)

        return False

    def _get_app(self) -> QApplication:
        app = QApplication.instance()
        if app is None:
            raise RuntimeError("No QApplication instance found")
        assert isinstance(app, QApplication)
        return app

    def install_event_filter(self):
        if self._installed:
            return
        self._get_app().installEventFilter(self)
        self._installed = True

    def detect_theme(self) -> Theme:
        try:
            app = self._get_app()
            window = app.activeWindow() or app.focusWidget()
            palette = window.palette() if window else app.palette()
            return "dark" if palette.color(QPalette.ColorRole.Text).lightness() > 128 else "light"
        except Exception as e:
            logger.warning("Failed to detect theme, defaulting to light: %s", e)
            return "light"

    def _read_palette(self) -> ThemeColors:
        app = self._get_app()
        window = app.activeWindow() or app.focusWidget()
        palette = window.palette() if window else app.palette()

        DEFAULT_COLOR = "#000000" if self.current_theme == "light" else "#FFFFFF"

        return {
            role.name.lower(): (
                palette.color(role).name() if palette.color(role).isValid() else DEFAULT_COLOR
            )
            for role in QPalette.ColorRole
        }

    def get_current_theme(self) -> tuple[Theme, ThemeColors]:
        """Snapshot of the current theme — useful for initial paint."""
        return self.current_theme, self.theme_colors
