from typing import Protocol, runtime_checkable

from PySide6.QtGui import QFont


@runtime_checkable
class FontPluginProtocol(Protocol):
    fontstyles: QFont | None

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
