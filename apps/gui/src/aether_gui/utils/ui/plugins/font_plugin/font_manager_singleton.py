from PySide6 import QtWidgets

from .font_manager import FontManager

_shared_font_manager: FontManager | None = None


def get_shared_font_manager(window: QtWidgets.QWidget) -> FontManager:
    """Return the shared FontManager instance.

    Returns:
        Shared FontManager with the event filter installed.
    """
    global _shared_font_manager
    if _shared_font_manager is None:
        _shared_font_manager = FontManager(window)
        _shared_font_manager.install_event_filter()
    return _shared_font_manager
