from __future__ import annotations

from abc import ABC, abstractmethod

from aether_utils.logger import get_logger
from PySide6.QtWidgets import QWidget


class AbstractComponentPlugin(ABC):
    """
    A self-contained capability that can be mixed into a StyledComponent.

    Each plugin is responsible for its own setup and teardown.
    The host widget is passed explicitly rather than inherited so plugins
    remain plain Python classes with no Qt dependency of their own.
    """

    logger = get_logger(f"plugin.{__name__}")

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the plugin name.

        Returns:
            The human-readable plugin name.
        """
        ...

    @property
    def priority(self) -> int:
        """Return the plugin priority for installation order.

        Returns:
            Higher values install earlier. Defaults to 0.
        """
        return 0

    @abstractmethod
    def install(self, widget: QWidget) -> None:
        """Install the plugin on a widget.

        Args:
            widget: Host widget that owns this plugin.
        """
        ...

    @abstractmethod
    def uninstall(self, widget: QWidget) -> None:
        """Uninstall the plugin from a widget.

        Args:
            widget: Host widget that owns this plugin.
        """
        ...
