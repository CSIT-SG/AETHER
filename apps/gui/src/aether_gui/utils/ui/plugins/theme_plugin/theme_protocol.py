from typing import Protocol, runtime_checkable

from .types import Theme, ThemeColors


@runtime_checkable
class ThemePluginProtocol(Protocol):
    theme: Theme | None
    colors: ThemeColors | None

    def _apply_styles(self, **kwargs) -> None:
        """Apply styles for the given theme and colors.

        Args:
            theme: Current theme name.
            colors: Theme color mapping.
            **kwargs: Additional theme payload.
        """
        ...

    def on_theme_change(self, *, theme: Theme, colors: ThemeColors) -> None:
        """Handle post-style theme updates.

        Args:
            theme: Current theme name.
            colors: Theme color mapping.
        """
        ...
