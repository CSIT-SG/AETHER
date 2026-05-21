from abc import abstractmethod
from pathlib import Path

from aether_utils.logger import get_logger
from PySide6.QtWidgets import QWidget

from .jinja_loaders import (
    HTMLFileLoader,
    HTMLStringLoader,
    QSSFileLoader,
    QSSStringLoader,
    TemplateLoader,
)
from .theme import Theme, ThemeColors
from .theme import get_shared_theme_manager as _get_shared_theme_manager


class _ColorsProxy:
    """Wraps ThemeColors dict as attribute access for Jinja templates.

    Jinja2 resolves ``{{ theme.base }}`` via Python's ``getattr``, not dict
    key access, so this proxy lets templates use ``{{ theme.base }}`` instead
    of the more verbose ``{{ theme['base'] }}``.

    Args:
        colors: The ThemeColors dict to wrap.
    """

    def __init__(self, colors: ThemeColors):
        self.__dict__.update(colors)

    def __repr__(self):
        return f"<ThemeColors {self.__dict__}>"


class StyledComponent(QWidget):
    """Base class for all themed, Jinja-templated PySide6 components.

    Wires a PySide6 ``QWidget`` to the shared ``ThemeManager`` so that QSS
    and HTML templates are automatically re-rendered whenever the active theme
    changes. Subclasses declare their templates by overriding one or more of
    the template hook methods below; the base class handles the rest.

    Lifecycle:
        On construction::

            __init__
            ├── init_ui()           # build widget tree (once)
            ├── _apply_styles()     # first QSS paint
            └── _on_theme_changed() # wired to ThemeManager.theme_changed

        On theme change::

            _on_theme_changed()
            ├── _apply_styles()
            └── on_theme_changed()  # optional subclass hook

    Template context:
        Every Jinja template receives the following variables automatically:

        - ``{{ theme.window }}``    — window / panel background colour
        - ``{{ theme.base }}``      — input / card background colour
        - ``{{ theme.text }}``      — primary text colour
        - ``{{ theme.mid }}``       — borders and dividers
        - ``{{ theme.button }}``    — button background colour
        - ``{{ theme.highlight }}`` — accent / selection colour
        - ``{{ mode }}``            — ``"light"`` or ``"dark"``

    Note:
        ``setObjectName()`` is called automatically with the class name so
        ``#MyComponent { }`` QSS selectors work without manual wiring.

    Examples:
        **QSS-only component** — styles live in an external ``.qss.jinja``
        file; no HTML is involved::

            class StatusBadge(StyledComponent):
                # init_ui builds the widget tree once at construction time.
                # Never call setStyleSheet() here — the render pipeline owns that.
                def init_ui(self) -> None:
                    layout = QHBoxLayout(self)
                    self._label = QLabel("Ready", self)
                    layout.addWidget(self._label)

                # Returning a Path tells the base class to load and render this
                # file on every theme change instead of calling styles().
                def style_file(self) -> Path:
                    return Path(__file__).resolve().parent / "styles.qss.jinja"

        **Inline QSS** — useful when the stylesheet is short enough to live
        alongside the Python code::

            class Divider(StyledComponent):
                def init_ui(self) -> None:
                    self.setFixedHeight(1)

                # The Jinja expression {{ theme.mid }} is replaced with the
                # current theme's border/divider colour at render time.
                def styles(self) -> str:
                    return "#Divider { background-color: {{ theme.mid }}; }"

        **HTML template rendered into a QWebEngineView** — ``on_theme_changed``
        pushes fresh HTML whenever the palette switches::

            class ProfileCard(StyledComponent):
                def init_ui(self) -> None:
                    layout = QVBoxLayout(self)
                    # The web view displays richly styled HTML produced by the
                    # template; QSS alone cannot style web content.
                    self._view = QWebEngineView(self)
                    layout.addWidget(self._view)
                    self._user = {"name": "Ada", "role": "Admin"}
                    # Render once immediately so the card isn't blank on launch.
                    self._view.setHtml(self.render_html(**self._user))

                def template_file(self) -> Path:
                    return Path(__file__).resolve().parent / "profile_card.html.jinja"

                # Called automatically after every theme change; re-renders the
                # HTML so colours in the web view stay in sync with the rest of
                # the UI without any manual signal wiring.
                def on_theme_changed(self, *, colors: ThemeColors, mode: Theme) -> None:
                    self._view.setHtml(self.render_html(**self._user))

        **QPainter canvas** — ``on_theme_changed`` triggers a repaint so
        custom-drawn elements pick up the new palette::

            class ActivityRing(StyledComponent):
                def init_ui(self) -> None:
                    self._progress = 0.67676767

                def set_progress(self, value: float) -> None:
                    self._progress = value
                    self.update()  # schedules a paintEvent

                # update() queues a paintEvent; the next paintEvent call will
                # use whatever colours were last stored in self._colors.
                def on_theme_changed(self, *, colors: ThemeColors, mode: Theme) -> None:
                    self._colors = colors
                    self.update()

                def paintEvent(self, event) -> None:
                    painter = QPainter(self)
                    arc_color = QColor(self._colors.get("highlight", "#0af"))
                    # … draw arc using arc_color and self._progress …
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        self._theme_mgr = _get_shared_theme_manager()

        if not self.objectName():
            self.setObjectName(type(self).__name__)

        self.init_ui()

        colors, mode = self._theme_mgr.current_theme()
        self._apply_styles(colors=colors, mode=mode)

        self._theme_mgr.theme_changed.connect(self._on_theme_changed)

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

    def styles(self) -> str:
        """Return an inline Jinja-templated QSS string.

        Override this method when the component's stylesheet is short enough
        to co-locate with its Python source. For larger or shared stylesheets
        prefer ``style_file()``, which takes precedence over this method.

        Returns:
            A Jinja2 QSS template string, or an empty string (default) to
            apply no inline styles.
        """
        return ""

    def style_file(self) -> Path | None:
        """Return the path to an external ``.qss.jinja`` template.

        When a non-``None`` path is returned it takes precedence over any
        string returned by ``styles()``.

        Returns:
            Absolute ``Path`` to a ``.qss.jinja`` file, or ``None`` (default)
            to fall back to ``styles()``.
        """
        return None

    def template(self) -> str:
        """Return an inline Jinja-templated HTML string.

        The rendered output is returned by ``render_html()``; subclasses decide
        how to consume it (e.g. pass it to ``QWebEngineView.setHtml``). For
        larger templates prefer ``template_file()``, which takes precedence.

        Returns:
            A Jinja2 HTML template string, or an empty string (default).
        """
        return ""

    def template_file(self) -> Path | None:
        """Return the path to an external ``.html.jinja`` template.

        When a non-``None`` path is returned it takes precedence over any
        string returned by ``template()``.

        Returns:
            Absolute ``Path`` to a ``.html.jinja`` file, or ``None`` (default)
            to fall back to ``template()``.
        """
        return None

    def on_theme_changed(self, *, colors: ThemeColors, mode: Theme) -> None:
        """Hook called after QSS is re-applied on every theme change.

        Override this method for imperative updates that QSS cannot express,
        such as swapping icon sets, repainting a ``QPainter`` canvas, or
        pushing new HTML into a ``QWebEngineView``.

        Args:
            colors: The full colour map for the new theme.
            mode: The new theme mode, either ``Theme.LIGHT`` or ``Theme.DARK``.
        """

    def render_html(self, **context: object) -> str:
        """Compile the HTML template against the current theme and return it.

        Resolves the active template (file or inline string), injects the
        current theme colours and mode alongside any caller-supplied context
        variables, renders the Jinja template, and returns the resulting HTML
        string. The caller is responsible for consuming the output.

        Args:
            **context: Arbitrary keyword arguments forwarded to the Jinja
                template as top-level variables. The reserved names ``theme``
                and ``mode`` are silently removed if passed, as they are
                always supplied by the render pipeline.

        Returns:
            The rendered HTML string, or an empty string if no template is
            configured.

        Example::

            class InfoPanel(StyledComponent):
                def init_ui(self) -> None:
                    self._view = QWebEngineView(self)

                def on_theme_changed(self, *, colors, mode) -> None:
                    # Re-render with the latest data on every palette switch.
                    self._view.setHtml(self.render_html(title="Stats", rows=self._rows))
        """
        colors, mode = self._theme_mgr.current_theme()
        return self._render(
            self._resolve_html_loader(),
            colors=colors,
            mode=mode,
            context=context,
        )

    def _on_theme_changed(self, colors: ThemeColors, mode: Theme) -> None:
        self._apply_styles(colors=colors, mode=mode)
        self.on_theme_changed(colors=colors, mode=mode)

    def _apply_styles(self, *, colors: ThemeColors, mode: Theme) -> None:
        qss = self._render(self._resolve_qss_loader(), colors=colors, mode=mode)
        if qss.strip():
            self.setStyleSheet(qss)

    def _resolve_qss_loader(self) -> TemplateLoader | None:
        if (f := self.style_file()) is not None:
            return QSSFileLoader(f)
        if (s := self.styles()).strip():
            return QSSStringLoader(s)
        return None

    def _resolve_html_loader(self) -> TemplateLoader | None:
        if (f := self.template_file()) is not None:
            return HTMLFileLoader(f)
        if (s := self.template()).strip():
            return HTMLStringLoader(s)
        return None

    def _render(
        self,
        loader: TemplateLoader | None,
        *,
        colors: ThemeColors,
        mode: Theme,
        context: dict[str, object] | None = None,
    ) -> str:
        if loader is None:
            return ""
        extra_context = dict(context or {})
        extra_context.pop("theme", None)
        extra_context.pop("mode", None)

        env = loader.make_env()
        tmpl = env.get_template(loader.get_template_name())
        return tmpl.render(theme=_ColorsProxy(colors), mode=mode, **extra_context)

    def closeEvent(self, event) -> None:
        """Disconnect theme signals and release resources on close.

        Overrides ``QWidget.closeEvent`` to cleanly remove the connection to
        ``ThemeManager.theme_changed``, preventing callbacks from firing on a
        destroyed widget.

        Args:
            event: The ``QCloseEvent`` passed by Qt.
        """
        try:
            self._theme_mgr.theme_changed.disconnect(self._on_theme_changed)
        except RuntimeError as e:
            self.logger.warning("Failed to disconnect theme_changed signal: %s", e)
            pass
        super().closeEvent(event)
