from abc import abstractmethod
from collections.abc import Iterable
from pathlib import Path

from aether_utils.logger import get_logger

from .plugins import (
    AbstractPluginManager,
    JinjaPlugin,
    Theme,
    ThemeColors,
    ThemePlugin,
)
from .plugins.abstract_component_plugin import AbstractComponentPlugin


class _ColorsProxy:
    """Wraps ThemeColors dict as attribute access for Jinja templates.

    Jinja2 resolves ``{{ colors.base }}`` via Python's ``getattr``, not dict
    key access, so this proxy lets templates use ``{{ colors.base }}`` instead
    of the more verbose ``{{ colors['base'] }}``.

    Args:
        colors: The ThemeColors dict to wrap.
    """

    def __init__(self, colors: ThemeColors):
        """Initialize the proxy with a theme color mapping.

        Args:
            colors: Mapping of palette roles to hex color strings.
        """
        self.__dict__.update(colors)

    def __repr__(self):
        """Return a debug-friendly representation.

        Returns:
            Debug string showing the color mapping.
        """
        return f"<ThemeColors {self.__dict__}>"


# implements JinjaPluginProtocol and ThemePluginProtocol implicitly
class StyledComponent(AbstractPluginManager):
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
        *,
        plugins: Iterable[AbstractComponentPlugin] | None = None,
    ) -> None:
        """Initialize the component and install plugins.

        Args:
            parent: Optional Qt parent widget.
            plugins: Additional plugins to install after defaults.
        """
        all_plugins = [ThemePlugin(), JinjaPlugin(), *(plugins or [])]
        super().__init__(parent, plugins=all_plugins)

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
        theme, colors = self._current_theme()
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
            colors=_ColorsProxy(colors),
            theme=theme,
            **extra_context,
        )

    def on_theme_change(self, *, theme: Theme, colors: ThemeColors) -> None:
        """Handle imperative updates after a theme change.

        Args:
            theme: The new theme, either ``"light"`` or ``"dark"``.
            colors: The full color map for the new theme.
        """
        pass

    def _apply_styles(self, *, theme: Theme, colors: ThemeColors, **_kwargs) -> None:
        """Render QSS and apply it to the widget.

        Args:
            theme: The active theme name.
            colors: Mapping of theme colors.
            **_kwargs: Unused theme payload for compatibility with callbacks.
        """
        qss = self.get_plugin(JinjaPlugin).render_qss(
            self,
            colors=_ColorsProxy(colors),
            theme=theme,
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
