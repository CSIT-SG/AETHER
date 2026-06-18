from typing import Protocol, runtime_checkable

from PySide6.QtGui import QFont

from .types import FontState


@runtime_checkable
class FontPluginProtocol(Protocol):
    state: FontState

    def _apply_styles(self, **kwargs) -> None:
        """Apply font styles for the update font changes.

        Args:
            **kwargs: Additional font payload.
        """
        ...

    def on_font_change(self, *, font: QFont) -> None:
        """Handle post-style font updates.

        Args:
            fontInfo: Contains font related style changes
        """
        ...

    def _current_font(self) -> QFont:
        """Return the current font.

        Returns:
            The active font, falling back to the shared manager
            if the font plugin is unavailable.
        """
        ...
