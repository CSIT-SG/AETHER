from .theme_manager import ThemeManager

_shared_theme_manager: ThemeManager | None = None


def get_shared_theme_manager() -> ThemeManager:
    """Return the shared ThemeManager instance.

    Returns:
        Shared ThemeManager with the event filter installed.
    """
    global _shared_theme_manager
    if _shared_theme_manager is None:
        _shared_theme_manager = ThemeManager()
        _shared_theme_manager.install_event_filter()
    return _shared_theme_manager
