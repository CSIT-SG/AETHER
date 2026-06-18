from typing import Protocol, runtime_checkable

from .types import Theme, ThemeColors, ThemeState


@runtime_checkable
class ThemePluginProtocol(Protocol):
    state: ThemeState

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

    def _current_theme(self) -> tuple[Theme, ThemeColors]:
        """Return the current theme and colors.

        Returns:
            The active theme and color map, falling back to the shared manager
            if the theme plugin is unavailable.
        """

        ...
