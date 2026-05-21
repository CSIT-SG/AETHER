# template_renderer.py
from __future__ import annotations

from pathlib import Path

from .abstract_jinja_base_loader import AbstractJinjaBaseLoader
from .jinja_html_loaders import HTMLFileLoader, HTMLStringLoader
from .jinja_qss_loaders import QSSFileLoader, QSSStringLoader


class JinjaManager:
    """Compiles Jinja templates against an arbitrary context."""

    def render_qss(
        self,
        *,
        inline: str | None = None,
        file: Path | None = None,
        **context: object,
    ) -> str:
        loader = self._resolve_qss_loader(inline=inline, file=file)
        return self._render(loader, **context)

    def render_html(
        self,
        *,
        inline: str | None = None,
        file: Path | None = None,
        **context: object,
    ) -> str:
        loader = self._resolve_html_loader(inline=inline, file=file)
        return self._render(loader, **context)

    def _resolve_qss_loader(
        self, *, inline: str | None, file: Path | None
    ) -> AbstractJinjaBaseLoader | None:
        if file is not None:
            return QSSFileLoader(file)
        if inline is not None and inline.strip():
            return QSSStringLoader(inline)
        return None

    def _resolve_html_loader(
        self, *, inline: str | None, file: Path | None
    ) -> AbstractJinjaBaseLoader | None:
        if file is not None:
            return HTMLFileLoader(file)
        if inline is not None and inline.strip():
            return HTMLStringLoader(inline)
        return None

    def _render(
        self,
        loader: AbstractJinjaBaseLoader | None,
        **context: object,
    ) -> str:
        if loader is None:
            return ""
        env = loader.make_env()
        tmpl = env.get_template(loader.get_template_name())
        return tmpl.render(**context)
