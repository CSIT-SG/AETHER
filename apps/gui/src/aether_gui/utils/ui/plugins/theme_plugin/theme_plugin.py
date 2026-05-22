# plugins/theme_plugin.py
from __future__ import annotations

from PySide6.QtWidgets import QWidget

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
        return "theme"

    @property
    def priority(self):
        return super().priority + 100  # must be installed before plugins that depend on theme data

    def install(self, widget: QWidget) -> None:
        if not isinstance(widget, ThemePluginProtocol):
            raise TypeError("Widget must implement ThemePluginProtocol")
        self._manager = get_shared_theme_manager()

        # initial paint
        theme, colors = self._manager.get_current_theme()
        self._notify(widget, theme, colors)

        self._manager.theme_change_event.connect(
            lambda theme, colors: self._notify(widget, theme, colors)
        )

    def uninstall(self, widget: QWidget) -> None:
        try:
            self._manager.theme_change_event.disconnect()
        except RuntimeError as e:
            self.logger.error(f"Error occurred while disconnecting theme change event: {e}")

    @property
    def current_theme(self) -> tuple[Theme, ThemeColors]:
        return self._manager.get_current_theme()

    def _notify(self, widget: ThemePluginProtocol, theme: Theme, colors: ThemeColors) -> None:
        widget._apply_styles(theme=theme, colors=colors)
        widget.on_theme_change(theme=theme, colors=colors)
