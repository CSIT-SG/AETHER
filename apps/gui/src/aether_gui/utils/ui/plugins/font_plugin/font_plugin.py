from __future__ import annotations

import weakref
from collections.abc import Callable
from types import SimpleNamespace

from aether_gui.utils.constants import WINDOW_PREFIX
from aether_utils.logger import get_logger
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QWidget
from shiboken6 import isValid

from ..abstract_component_plugin import AbstractComponentPlugin
from .font_manager_singleton import get_shared_font_manager
from .font_protocol import FontPluginProtocol

logger = get_logger("font_plugin")


class FontPlugin(AbstractComponentPlugin):
    """
    Wires the host widget to the shared FontManager.

    Calls _apply_styles() and on_font_change() on the host
    whenever the active font changes.
    """

    @property
    def name(self) -> str:
        """Return the plugin name.

        Returns:
            The plugin name.
        """
        return "font"

    @property
    def priority(self) -> int:
        """Return install priority for font-aware plugins.

        Returns:
            Higher priority to install before font-dependent plugins.
        """
        return super().priority + 99  # Priority is tbd

    _widget_ref: weakref.ReferenceType[FontPluginProtocol] | None = None
    _font_change_handler: Callable[[QFont], None] | None = None
    _destroyed_handler: Callable[..., None] | None = None

    def install(self, widget: QWidget) -> None:
        """Install font hooks on the widget.

        Args:
            widget: Host widget implementing FontPluginProtocol.

        Raises:
            TypeError: If the widget does not implement FontPluginProtocol.
        """
        if not isinstance(widget, FontPluginProtocol):
            raise TypeError("Widget must implement FontPluginProtocol")

        w: QWidget | None = widget
        title = widget.windowTitle() if isinstance(widget, QWidget) else ""
        while w is not None:
            title = w.windowTitle()
            if title.startswith(WINDOW_PREFIX):
                break
            w = w.parentWidget()

        self._manager = get_shared_font_manager(title)

        # initial paint
        font = self._manager.get_current_font()
        self._notify(widget, font)

        # bind notify callback to self so we can disconnect it later.
        # hold only a weakref to avoid keeping widgets alive.
        self._widget_ref = weakref.ref(widget)

        def handle_font_change(font: QFont) -> None:
            target = self._widget_ref() if self._widget_ref is not None else None
            if target is None or not isValid(target):
                self._disconnect_font_handler()
                return

            self._notify(target, font)

        # store the handler on the instance so we can disconnect it later
        self._font_change_handler = handle_font_change
        self._manager.font_change_event.connect(self._font_change_handler)

        def handle_destroyed(_obj: object | None = None) -> None:
            self._disconnect_font_handler()

        self._destroyed_handler = handle_destroyed
        widget.destroyed.connect(self._destroyed_handler)

    def uninstall(self, widget: QWidget) -> None:
        """Remove font hooks from the widget.

        Args:
            widget: Host widget previously installed.
        """
        self._disconnect_font_handler()
        handler = getattr(self, "_destroyed_handler", None)
        if handler is not None:
            try:
                widget.destroyed.disconnect(handler)
            except RuntimeError as e:
                logger.debug("Error occurred while disconnecting destroyed handler: %s", e)

    @property
    def current_font(self) -> QFont:
        """Return the current font and color map.

        Returns:
            FontInfo dictionary.
        """
        return self._manager.get_current_font()

    def _notify(self, widget: FontPluginProtocol, font: QFont) -> None:
        """Apply styles and notify the widget of a font change.

        Args:
            widget: Host widget implementing FontPluginProtocol.
            font: Current font styles
        """
        if not isValid(widget):
            self._disconnect_font_handler()
            return

        widget.state["fontstyles"] = self._font_to_namespace(font)
        widget.on_font_change(font=font)
        widget._apply_styles()

    def _disconnect_font_handler(self) -> None:
        """Disconnect font change handlers if connected."""
        manager = getattr(self, "_manager", None)
        handler = getattr(self, "_font_change_handler", None)
        if manager is None or handler is None:
            return
        try:
            manager.font_change_event.disconnect(handler)
        except RuntimeError as e:
            logger.error("Error occurred while disconnecting font change event: %s", e)
        finally:
            self._font_change_handler = None

    def _font_to_namespace(self, font: QFont) -> SimpleNamespace:
        return SimpleNamespace(
            family=font.family(),
            size=font.pointSize() if font.pointSize() > 0 else font.pixelSize(),
            point_size=font.pointSize(),
            pixel_size=font.pixelSize(),
            weight=int(font.weight()),
            bold=font.bold(),
            italic=font.italic(),
            underline=font.underline(),
            strikeout=font.strikeOut(),
        )
