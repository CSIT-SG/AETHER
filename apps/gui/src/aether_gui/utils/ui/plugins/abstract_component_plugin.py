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
        """Return the name of the plugin."""
        ...

    @property
    def priority(self) -> int:
        """Return the plugin's priority for installation order.

        Defaults to 0 if the implementing class does not provide a value.
        """
        return 0

    @abstractmethod
    def install(self, widget: QWidget) -> None:
        """Called once during StyledComponent.__init__, after init_ui()."""
        ...

    @abstractmethod
    def uninstall(self, widget: QWidget) -> None:
        """Called during StyledComponent.closeEvent for cleanup."""
        ...
