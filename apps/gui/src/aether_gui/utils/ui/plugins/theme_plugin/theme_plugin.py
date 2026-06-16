# plugins/theme_plugin.py
from __future__ import annotations

import weakref
from collections.abc import Callable

from PySide6.QtWidgets import QWidget
from shiboken6 import isValid

from ..abstract_component_plugin import AbstractComponentPlugin
from .theme_manager_singleton import get_shared_theme_manager
from .theme_protocol import ThemePluginProtocol
from .types import Theme, ThemeColors


class ThemePlugin(AbstractComponentPlugin):
    """
    Wires the host widget to the shared ThemeManager.

    Calls _apply_styles() and on_theme_change() on the host
    whenever the active theme changes.
    """

    @property
    def name(self) -> str:
        """Return the plugin name.

        Returns:
            The plugin name.
        """
        return "theme"

    @property
    def priority(self):
        """Return install priority for theme-aware plugins.

        Returns:
            Higher priority to install before theme-dependent plugins.
        """
        return super().priority + 100  # must be installed before plugins that depend on theme data

    # generate these at install time because we need to access to a weak ref pointing to the widget
    _widget_ref: weakref.ReferenceType[ThemePluginProtocol] | None = None
    _theme_change_handler: Callable[[Theme, ThemeColors], None] | None = None
    _destroyed_handler: Callable[..., None] | None = None

    def install(self, widget: QWidget) -> None:
        """Install theme hooks on the widget.

        Args:
            widget: Host widget implementing ThemePluginProtocol.

        Raises:
            TypeError: If the widget does not implement ThemePluginProtocol.
        """
        if not isinstance(widget, ThemePluginProtocol):
            raise TypeError("Widget must implement ThemePluginProtocol")
        self._manager = get_shared_theme_manager()

        # initial paint
        theme, colors = self._manager.get_current_theme()
        self._notify(widget, theme, colors)

        # bind notify callback to self so we can disconnect it later.
        # hold only a weakref to avoid keeping widgets alive.
        self._widget_ref = weakref.ref(widget)

        def handle_theme_change(theme: Theme, colors: ThemeColors) -> None:
            target = self._widget_ref() if self._widget_ref is not None else None
            if target is None or not isValid(target):
                self._disconnect_theme_handler()
                return
            self._notify(target, theme, colors)

        # store the handler on the instance so we can disconnect it later
        self._theme_change_handler = handle_theme_change
        self._manager.theme_change_event.connect(self._theme_change_handler)

        def handle_destroyed(_obj: object | None = None) -> None:
            self._disconnect_theme_handler()

        self._destroyed_handler = handle_destroyed
        widget.destroyed.connect(self._destroyed_handler)

    # `_theme_change_handler` is assigned at install time as an instance
    # callable so it can be disconnected and set to `None` safely.

    def uninstall(self, widget: QWidget) -> None:
        """Remove theme hooks from the widget.

        Args:
            widget: Host widget previously installed.
        """
        self._disconnect_theme_handler()
        handler = getattr(self, "_destroyed_handler", None)
        if handler is not None:
            try:
                widget.destroyed.disconnect(handler)
            except RuntimeError as e:
                self.logger.debug("Error occurred while disconnecting destroyed handler: %s", e)

    @property
    def current_theme(self) -> tuple[Theme, ThemeColors]:
        """Return the current theme and color map.

        Returns:
            Tuple of (theme, theme colors).
        """
        return self._manager.get_current_theme()

    def _notify(self, widget: ThemePluginProtocol, theme: Theme, colors: ThemeColors) -> None:
        """Apply styles and notify the widget of a theme change.

        Args:
            widget: Host widget implementing ThemePluginProtocol.
            theme: Current theme name.
            colors: Current theme colors.
        """
        if not isValid(widget):
            self._disconnect_theme_handler()
            return

        widget.theme, widget.colors = theme, colors
        widget.on_theme_change(theme=theme, colors=colors)
        widget._apply_styles(theme=theme, colors=colors)

    def _disconnect_theme_handler(self) -> None:
        """Disconnect theme change handlers if connected."""
        manager = getattr(self, "_manager", None)
        handler = getattr(self, "_theme_change_handler", None)
        if manager is None or handler is None:
            return
        try:
            manager.theme_change_event.disconnect(handler)
        except RuntimeError as e:
            self.logger.error("Error occurred while disconnecting theme change event: %s", e)
        finally:
            self._theme_change_handler = None
