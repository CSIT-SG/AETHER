from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import TypeVar, cast

from aether_utils.logger import get_logger
from PySide6.QtWidgets import QWidget

from .abstract_component_plugin import AbstractComponentPlugin

TPlugin = TypeVar("TPlugin", bound=AbstractComponentPlugin)


class AbstractPluginManager(QWidget, ABC):
    """
    Lifecycle-driven plugin host.

    Phases:
        1. setup
        2. init_ui
        3. install_plugins
        4. plugins_ready
        5. teardown (closeEvent)
    """

    def __init__(
        self,
        parent=None,
        *,
        plugins: Iterable[AbstractComponentPlugin] | None = None,
    ) -> None:
        super().__init__(parent)

        self.logger = get_logger(f"component.{type(self).__name__}")

        if not self.objectName():
            self.setObjectName(type(self).__name__)

        self._plugins = self._build_registry(plugins or [])

        self.setup()
        self.init_ui()

        self.install_plugins()
        self.plugins_ready()

    # -------------------------
    # Lifecycle hooks (subclass)
    # -------------------------

    def setup(self) -> None:
        """
        Early initialization hook.
        No UI should be created here.
        """
        pass

    @abstractmethod
    def init_ui(self) -> None:
        """
        Build widget UI structure.
        """
        raise NotImplementedError

    def plugins_ready(self) -> None:
        """
        Called after all plugins are installed.
        Safe place for cross-plugin wiring.
        """
        pass

    def teardown(self) -> None:
        """
        Called before plugins are uninstalled.
        """
        pass

    # -------------------------
    # Plugin system
    # -------------------------

    def install_plugins(self) -> None:
        for plugin in self._plugins.values():
            try:
                plugin.install(self)
            except Exception as e:
                self.logger.exception("Plugin %s failed to install: %s", type(plugin).__name__, e)

    def get_plugin(self, plugin_cls: type[TPlugin]) -> TPlugin:
        return cast(TPlugin, self._plugins[plugin_cls])

    # -------------------------
    # Qt lifecycle
    # -------------------------

    def closeEvent(self, event) -> None:
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
        ordered = sorted(plugins, key=lambda p: p.priority, reverse=True)
        return {type(p): p for p in ordered}
