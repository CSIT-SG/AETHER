from abc import abstractmethod
from collections.abc import Iterable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from aether_utils.logger import get_logger

from .plugins import (
    AbstractComponentPluginManager,
    JinjaPlugin,
    Theme,
    ThemeColors,
    ThemePlugin,
)
from .plugins.abstract_component_plugin import AbstractComponentPlugin


# implements JinjaPluginProtocol and ThemePluginProtocol implicitly
class StyledComponent(AbstractComponentPluginManager):
    """Themed, Jinja-driven QWidget base powered by plugins.

    StyledComponent installs ``ThemePlugin`` and ``JinjaPlugin`` by default.
    Subclasses implement Jinja hooks (``styles``, ``style_file``, ``template``,
    ``template_file``) and the theme hook ``on_theme_change``.

    Template context:
        - ``colors.<role>`` for each ``QPalette.ColorRole`` (lowercased).
        - ``theme``: ``"light"`` or ``"dark"``.
    """

    def __init__(
        self,
        parent=None,
        window=None,
        *,
        plugins: Iterable[AbstractComponentPlugin] | None = None,
        states: dict[str, Any] | None = None,
    ) -> None:
        """Initialize the component and install plugins.

        Args:
            parent: Optional Qt parent widget.
            plugins: Additional plugins to install after defaults.
        """

        self.state = {"theme": None, "colors": None, **(states or {})}
        all_plugins = [ThemePlugin(), JinjaPlugin(), *(plugins or [])]
        super().__init__(parent, plugins=all_plugins)

        theme, colors = self._current_theme()
        self.state["theme"], self.state["colors"] = theme, SimpleNamespace(**colors)

        self.logger = get_logger(f"component.{type(self).__name__}")

    @abstractmethod
    def init_ui(self) -> None:
        """Build the widget tree.

        Called during ``__init__`` before the first style pass. Subclasses must
        implement this method to create and lay out child widgets.

        Raises:
            NotImplementedError: If not overridden by a subclass.
        """
        raise NotImplementedError

    def styles(self) -> str | None:
        """Return an inline Jinja-templated QSS string.

        Returns:
            A Jinja2 QSS template string, or ``None`` to apply no inline styles.
        """
        return None

    def style_file(self) -> Path | None:
        """Return the path to an external ``.qss.jinja`` template.

        Returns:
            Absolute ``Path`` to a ``.qss.jinja`` file, or ``None`` to fall back
            to ``styles()``.
        """
        return None

    def template(self) -> str | None:
        """Return an inline Jinja-templated HTML string.

        Returns:
            A Jinja2 HTML template string, or ``None`` to apply no template.
        """
        return None

    def template_file(self) -> Path | None:
        """Return the path to an external ``.html.jinja`` template.

        Returns:
            Absolute ``Path`` to a ``.html.jinja`` file, or ``None`` to fall back
            to ``template()``.
        """
        return None

    def render_html(self, **context: object) -> str:
        """Compile the HTML template against the current theme and return it.

        Args:
            **context: Keyword arguments forwarded to the Jinja template. The
                reserved names ``colors`` and ``theme`` are ignored if passed.

        Returns:
            The rendered HTML string, or an empty string if no template exists.
        """
        extra_context = dict(context)

        # we ignore any user-supplied "theme" or "colors" keys since those are reserved
        if extra_context.pop("colors", None):
            self.logger.debug(
                "Context variable 'colors' is reserved and will be ignored. Received: %s",
                context["colors"],
            )
        if extra_context.pop("theme", None):
            self.logger.debug(
                "Context variable 'theme' is reserved and will be ignored. Received: %s",
                context["theme"],
            )

        return self.get_plugin(JinjaPlugin).render_html(
            self,
            **self.state,
            **extra_context,
        )

    def on_theme_change(self, *, theme: Theme, colors: ThemeColors) -> None:
        """Handle imperative updates after a theme change.

        Args:
            theme: The new theme, either ``"light"`` or ``"dark"``.
            colors: The full color map for the new theme.
        """
        pass

    def _apply_styles(self, **_kwargs) -> None:
        """Render QSS and apply it to the widget. ThemePlugin calls this method before on_theme_change.

        Args:
            theme: The active theme name.
            colors: Mapping of theme colors.
            **_kwargs: Unused theme payload for compatibility with callbacks.
        """
        qss = self.get_plugin(JinjaPlugin).render_qss(
            self,
            **self.state,
        )
        if qss.strip():
            self.setStyleSheet(qss)

    def _current_theme(self) -> tuple[Theme, ThemeColors]:
        """Return the current theme and colors.

        Returns:
            The active theme and color map, falling back to the shared manager
            if the theme plugin is unavailable.
        """

        return self.get_plugin(ThemePlugin).current_theme
