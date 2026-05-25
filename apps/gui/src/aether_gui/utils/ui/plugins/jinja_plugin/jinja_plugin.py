from __future__ import annotations

from PySide6.QtWidgets import QWidget

from ..abstract_component_plugin import AbstractComponentPlugin
from .jinja_manager import JinjaManager
from .jinja_protocol import JinjaPluginProtocol


class JinjaPlugin(AbstractComponentPlugin):
    _renderer = JinjaManager()

    @property
    def name(self) -> str:
        """Return the plugin name.

        Returns:
            The plugin name.
        """
        return self.__class__.__name__

    def install(self, widget: QWidget) -> None:
        """Install the plugin on the widget.

        Args:
            widget: Host widget.
        """
        pass

    def uninstall(self, widget: QWidget) -> None:
        """Uninstall the plugin from the widget.

        Args:
            widget: Host widget.
        """
        pass

    def render_qss(self, widget: JinjaPluginProtocol, **context: object) -> str:
        """Render QSS for a widget using its template hooks.

        Args:
            widget: Widget implementing JinjaPluginProtocol hooks.
            **context: Template context variables.

        Returns:
            Rendered QSS string.
        """
        inline = widget.styles() if widget.styles else None
        file = widget.style_file() if widget.style_file else None

        return self._renderer.render_qss(inline=inline, file=file, **context)

    def render_html(self, widget: JinjaPluginProtocol, **context: object) -> str:
        """Render HTML for a widget using its template hooks.

        Args:
            widget: Widget implementing JinjaPluginProtocol hooks.
            **context: Template context variables.

        Returns:
            Rendered HTML string.
        """
        inline = widget.template() if widget.template else None
        file = widget.template_file() if widget.template_file else None

        return self._renderer.render_html(inline=inline, file=file, **context)
