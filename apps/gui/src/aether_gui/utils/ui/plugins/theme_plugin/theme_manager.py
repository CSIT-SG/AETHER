# theme_manager.py
from aether_gui.utils.constants import SEMANTIC_COLORS
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
        """Initialize the theme manager and read the current palette."""
        super().__init__()
        self._installed = False
        self.current_theme: Theme = self.detect_theme()
        self.theme_colors: ThemeColors = self._read_palette()  # read only, no emit yet

    def eventFilter(self, obj, event) -> bool:
        """Handle palette changes and emit theme updates.

        Args:
            obj: Qt object emitting the event.
            event: Qt event being filtered.

        Returns:
            True if the event is handled, otherwise False.
        """
        if event.type() != QEvent.Type.PaletteChange:
            return False

        new_theme = self.detect_theme()
        if self.current_theme == new_theme:
            return False

        logger.debug("Theme changed to: %s", new_theme)
        self.current_theme = new_theme
        self.theme_colors = self._read_palette()
        self.theme_change_event.emit(self.current_theme, self.theme_colors)

        return False

    def _get_app(self) -> QApplication:
        """Return the active QApplication instance.

        Returns:
            The active QApplication.

        Raises:
            RuntimeError: If no QApplication exists.
        """
        app = QApplication.instance()
        if app is None:
            raise RuntimeError("No QApplication instance found")
        assert isinstance(app, QApplication)
        return app

    def install_event_filter(self):
        """Install the global palette change event filter."""
        if self._installed:
            return
        self._get_app().installEventFilter(self)
        self._installed = True

    def detect_theme(self) -> Theme:
        """Detect the current theme from the active palette.

        Returns:
            "dark" or "light" based on palette lightness.
        """
        try:
            app = self._get_app()
            window = app.activeWindow() or app.focusWidget()
            palette = window.palette() if window else app.palette()
            return "dark" if palette.color(QPalette.ColorRole.Text).lightness() > 128 else "light"
        except Exception as e:
            logger.warning("Failed to detect theme, defaulting to light: %s", e)
            return "light"

    def _read_palette(self) -> ThemeColors:
        """Read the current palette into a theme color mapping.

        Returns:
            Mapping of palette roles to hex color strings.
        """
        app = self._get_app()
        window = app.activeWindow() or app.focusWidget()
        palette = window.palette() if window else app.palette()

        DEFAULT_COLOR = "#000000" if self.current_theme == "light" else "#FFFFFF"
        
        colors: ThemeColors = {
            role.name.lower(): (
                palette.color(role).name() if palette.color(role).isValid() else DEFAULT_COLOR
            )
            for role in QPalette.ColorRole
        }
        
        colors.update(SEMANTIC_COLORS.get(self.current_theme, {}))
        return colors

    def get_current_theme(self) -> tuple[Theme, ThemeColors]:
        """Return the current theme snapshot.

        Returns:
            Tuple of (theme, theme colors).
        """
        return self.current_theme, self.theme_colors
