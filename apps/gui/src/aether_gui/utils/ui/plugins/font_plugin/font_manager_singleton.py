from .font_manager import FontManager

_shared_font_manager: FontManager | None = None


def get_shared_font_manager() -> FontManager:
    """Return the shared FontManager instance.

    Returns:
        Shared FontManager with the event filter installed.
    """
    global _shared_font_manager
    if _shared_font_manager is None:
        _shared_font_manager = FontManager()
        _shared_font_manager.install_event_filter()
    return _shared_font_manager
