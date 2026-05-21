from abc import abstractmethod
from collections.abc import Iterable
from pathlib import Path

from aether_utils.logger import get_logger

from .plugins import (
    AbstractPluginManager,
    JinjaPlugin,
    JinjaPluginProtocol,
    Theme,
    ThemeColors,
    ThemePlugin,
    ThemePluginProtocol,
)
from .plugins.abstract_component_plugin import AbstractComponentPlugin
from .plugins.theme_plugin.theme_manager_singleton import get_shared_theme_manager


class _ColorsProxy:
    """Wraps ThemeColors dict as attribute access for Jinja templates.

    Jinja2 resolves ``{{ colors.base }}`` via Python's ``getattr``, not dict
    key access, so this proxy lets templates use ``{{ colors.base }}`` instead
    of the more verbose ``{{ colors['base'] }}``.

    Args:
        colors: The ThemeColors dict to wrap.
    """

    def __init__(self, colors: ThemeColors):
        self.__dict__.update(colors)

    def __repr__(self):
        return f"<ThemeColors {self.__dict__}>"


class StyledComponent(AbstractPluginManager, JinjaPluginProtocol, ThemePluginProtocol):
    """Themed, Jinja-driven QWidget base powered by plugins.

    StyledComponent installs ``ThemePlugin`` and ``JinjaPlugin`` by default.
    Subclasses implement Jinja hooks (``styles``, ``style_file``, ``template``,
    ``template_file``) and the theme hook ``on_theme_change``.

    Lifecycle:
        On construction::

            setup()
            init_ui()
            install_plugins()
            plugins_ready()  # run after all plugins installed
                -> ThemePlugin.install() calls _apply_styles() + on_theme_change()

        On theme change::

            ThemePlugin -> _apply_styles(); on_theme_change()

        On close::
            teardown() -> plugin.uninstall()

    Template context:
        Jinja templates receive:
        - ``colors.<role>`` for each ``QPalette.ColorRole`` (lowercased), e.g.
          ``colors.window``, ``colors.text``, ``colors.base``, ``colors.mid``.
        - ``theme``: ``"light"`` or ``"dark"``.

    Note:
        ``setObjectName()`` is set automatically to the class name.

    Examples (concise):
        QSS file::

            class StatusBadge(StyledComponent):
                def setup(self): self._text = "Ready"
                def init_ui(self): self._label = QLabel(self._text, self)
                def style_file(self) -> Path: return Path(__file__).with_name("styles.qss.jinja")
                def plugins_ready(self): pass
            def create_status_badge(parent=None): return StatusBadge(parent)

        Inline QSS::

            class Divider(StyledComponent):
                def init_ui(self): self.setFixedHeight(1)
                def styles(self) -> str: return "#Divider { background: {{ colors.mid }}; }"
            def create_divider(parent=None): return Divider(parent)

        HTML template::

            class ProfileCard(StyledComponent):
                def setup(self): self._user = {"name": "Ada"}
                def init_ui(self): self._view = QWebEngineView(self)
                def template_file(self) -> Path: return Path(__file__).with_name("profile_card.html.jinja")
                def on_theme_change(self, *, theme: Theme, colors: ThemeColors) -> None:
                    self._view.setHtml(self.render_html(user=self._user))
            def create_profile_card(parent=None): return ProfileCard(parent)
    """

    def __init__(
        self,
        parent=None,
        *,
        plugins: Iterable[AbstractComponentPlugin] | None = None,
    ) -> None:
        all_plugins = [ThemePlugin(), JinjaPlugin(), *(plugins or [])]
        super().__init__(parent, plugins=all_plugins)

        self.logger = get_logger(f"component.{type(self).__name__}")

    @abstractmethod
    def init_ui(self) -> None:
        """Build the widget tree.

        Called once during ``__init__``, before the first style pass. Subclasses
        must implement this method to construct and lay out all child widgets.

        Note:
            Do **not** call ``setStyleSheet()`` here. Style application is
            handled entirely by the render pipeline so that theme changes are
            applied consistently.

        Raises:
            NotImplementedError: Always, if not overridden by a subclass.
        """
        raise NotImplementedError

    def styles(self) -> str | None:
        """Return an inline Jinja-templated QSS string.

        Override this method when the component's stylesheet is short enough
        to co-locate with its Python source. For larger or shared stylesheets
        prefer ``style_file()``, which takes precedence over this method.

        Returns:
            A Jinja2 QSS template string, or an empty string (default) to
            apply no inline styles.
        """
        return None

    def style_file(self) -> Path | None:
        """Return the path to an external ``.qss.jinja`` template.

        When a non-``None`` path is returned it takes precedence over any
        string returned by ``styles()``.

        Returns:
            Absolute ``Path`` to a ``.qss.jinja`` file, or ``None`` (default)
            to fall back to ``styles()``.
        """
        return None

    def template(self) -> str | None:
        """Return an inline Jinja-templated HTML string.

        The rendered output is returned by ``render_html()``; subclasses decide
        how to consume it (e.g. pass it to ``QWebEngineView.setHtml``). For
        larger templates prefer ``template_file()``, which takes precedence.

        Returns:
            A Jinja2 HTML template string, or an empty string (default).
        """
        return None

    def template_file(self) -> Path | None:
        """Return the path to an external ``.html.jinja`` template.

        When a non-``None`` path is returned it takes precedence over any
        string returned by ``template()``.

        Returns:
            Absolute ``Path`` to a ``.html.jinja`` file, or ``None`` (default)
            to fall back to ``template()``.
        """
        return None

    def render_html(self, **context: object) -> str:
        """Compile the HTML template against the current theme and return it.

        Resolves the active template (file or inline string), injects the
        current theme colors and theme alongside any caller-supplied context
        variables, renders the Jinja template, and returns the resulting HTML
        string. The caller is responsible for consuming the output.

        Args:
            **context: Arbitrary keyword arguments forwarded to the Jinja
                template as top-level variables. The reserved names ``colors``
                and ``theme`` are silently removed if passed, as they are
                always supplied by the render pipeline.

        Returns:
            The rendered HTML string, or an empty string if no template is
            configured.

        Example::

            class InfoPanel(StyledComponent):
                def init_ui(self) -> None:
                    self._view = QWebEngineView(self)

                def on_theme_change(self, *, theme, colors) -> None:
                    # Re-render with the latest data on every palette switch.
                    self._view.setHtml(self.render_html(title="Stats", rows=self._rows))
        """
        theme, colors = self._current_theme()
        extra_context = dict(context)
        extra_context.pop("colors", None)
        extra_context.pop("theme", None)

        return self.get_plugin(JinjaPlugin).render_html(
            self,
            colors=_ColorsProxy(colors),
            theme=theme,
            **extra_context,
        )

    def on_theme_change(self, *, theme: Theme, colors: ThemeColors) -> None:
        """Hook called after QSS is re-applied on every theme change.

        Override this method for imperative updates that QSS cannot express,
        such as swapping icon sets, repainting a ``QPainter`` canvas, or
        pushing new HTML into a ``QWebEngineView``.

        Args:
            theme: The new theme, either ``"light"`` or ``"dark"``.
            colors: The full colour map for the new theme.
        """
        pass

    def _apply_styles(self, *, theme: Theme, colors: ThemeColors, **_kwargs) -> None:
        qss = self.get_plugin(JinjaPlugin).render_qss(
            self,
            colors=_ColorsProxy(colors),
            theme=theme,
        )
        if qss.strip():
            self.setStyleSheet(qss)

    def _current_theme(self) -> tuple[Theme, ThemeColors]:
        try:
            return self.get_plugin(ThemePlugin).current_theme
        except Exception:
            return get_shared_theme_manager().get_current_theme()
