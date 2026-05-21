from typing import Protocol, runtime_checkable

from .types import Theme, ThemeColors


@runtime_checkable
class ThemePluginProtocol(Protocol):
    def _apply_styles(self, *, theme: Theme, colors: ThemeColors, **kwargs) -> None: ...
    def on_theme_change(self, *, theme: Theme, colors: ThemeColors) -> None: ...
