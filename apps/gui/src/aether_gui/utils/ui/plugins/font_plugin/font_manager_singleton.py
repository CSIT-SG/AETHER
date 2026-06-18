from .font_manager import FontManager

_shared_font_managers: dict[str, FontManager] = {}


def get_shared_font_manager(window_title: str) -> FontManager:
    """Return the shared FontManager instance.

    Returns:
        Shared FontManager with the event filter installed.
    """
    if window_title not in _shared_font_managers:
        manager = FontManager(window_title)
        manager.install_event_filter()
        _shared_font_managers[window_title] = manager
    return _shared_font_managers[window_title]
