from __future__ import annotations

from abc import ABCMeta, abstractmethod
from collections.abc import Iterable
from typing import Any, TypeVar, cast

from aether_utils.logger import get_logger
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QWidget

from .abstract_component_plugin import AbstractComponentPlugin

TPlugin = TypeVar("TPlugin", bound=AbstractComponentPlugin)


class _WidgetABCMeta(ABCMeta, type(QWidget)):  # type: ignore[misc]
    """Metaclass to allow AbstractComponentPluginManager to be both an ABC and a QWidget."""

    pass


class AbstractComponentPluginManager(QWidget, metaclass=_WidgetABCMeta):
    """
    Lifecycle-driven plugin host.

    Phases:
        1. setup
        2. init_ui
        3. _install_plugins
        4. plugins_ready
        5. teardown (closeEvent)
    """

    def __init__(
        self,
        parent: Any = None,
        *,
        plugins: Iterable[AbstractComponentPlugin] | None = None,
    ) -> None:
        """Initialize the widget and install plugins.

        Args:
            parent: Optional Qt parent widget.
            plugins: Plugins to install on this widget.
        """
        super().__init__(parent)

        self.logger = get_logger(f"component.{type(self).__name__}")

        if not self.objectName():
            self.setObjectName(type(self).__name__)

        self._plugins = self._build_registry(plugins or [])

        self.setup()
        self.init_ui()

        self._install_plugins()
        self.plugins_ready()

    # -------------------------
    # Lifecycle hooks (subclass)
    # -------------------------

    def setup(self) -> None:
        """Run early initialization logic before UI creation."""
        pass

    @abstractmethod
    def init_ui(self) -> None:
        """Build the widget UI structure."""
        raise NotImplementedError

    def plugins_ready(self) -> None:
        """Run logic after all plugins are installed."""
        pass

    def teardown(self) -> None:
        """Run cleanup logic before plugins are uninstalled."""
        pass

    # -------------------------
    # Plugin system
    # -------------------------

    def _install_plugins(self) -> None:
        """Install all registered plugins in priority order."""
        for plugin in self._plugins.values():
            try:
                plugin.install(self)
            except Exception as e:
                self.logger.exception("Plugin %s failed to install: %s", type(plugin).__name__, e)

    def get_plugin(self, plugin_cls: type[TPlugin]) -> TPlugin:
        """Return the plugin instance for a given class.

        Args:
            plugin_cls: Plugin class to retrieve.

        Returns:
            The installed plugin instance.
        """
        return cast(TPlugin, self._plugins[plugin_cls])

    # -------------------------
    # Qt lifecycle
    # -------------------------

    def closeEvent(self, event: QCloseEvent) -> None:
        """Handle widget close and uninstall plugins.

        Args:
            event: Qt close event.
        """
        try:
            self.teardown()
        except Exception as e:
            self.logger.warning("teardown() failed: %s", e)

        for plugin in reversed(list(self._plugins.values())):
            try:
                plugin.uninstall(self)
            except Exception as e:
                self.logger.warning(
                    "Plugin %s failed to uninstall: %s",
                    type(plugin).__name__,
                    e,
                )

        super().closeEvent(event)

    # -------------------------
    # Registry
    # -------------------------

    @staticmethod
    def _build_registry(
        plugins: Iterable[AbstractComponentPlugin],
    ) -> dict[type[AbstractComponentPlugin], AbstractComponentPlugin]:
        """Build a plugin registry keyed by plugin class.

        Args:
            plugins: Iterable of plugin instances.

        Returns:
            Mapping of plugin class to plugin instance, ordered by priority.
        """
        ordered = sorted(plugins, key=lambda p: p.priority, reverse=True)
        return {type(p): p for p in ordered}
