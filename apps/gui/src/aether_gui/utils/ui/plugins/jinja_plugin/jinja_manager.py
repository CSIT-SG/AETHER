from __future__ import annotations

from pathlib import Path

from jinja2 import Environment

from .abstract_jinja_base_loader import AbstractJinjaBaseLoader
from .jinja_html_loaders import HTMLFileLoader, HTMLStringLoader
from .jinja_qss_loaders import QSSFileLoader, QSSStringLoader
from .types import JinjaEnvironmentCacheKey


class JinjaManager:
    """Compiles Jinja templates against an arbitrary context."""

    def __init__(self) -> None:
        """Initialize the manager and its environment cache."""
        self._env_cache: dict[JinjaEnvironmentCacheKey, Environment] = {}

    def render_qss(
        self,
        *,
        inline: str | None = None,
        file: Path | None = None,
        **context: object,
    ) -> str:
        """Render a QSS template with the given context.

        Args:
            inline: Inline QSS template string.
            file: Path to a QSS template file.
            **context: Context variables for the template.

        Returns:
            Rendered QSS string, or an empty string if no template is provided.
        """
        loader, cache_key = self._resolve_qss_loader(inline=inline, file=file)
        return self._render(loader, cache_key, **context)

    def render_html(
        self,
        *,
        inline: str | None = None,
        file: Path | None = None,
        **context: object,
    ) -> str:
        """Render an HTML template with the given context.

        Args:
            inline: Inline HTML template string.
            file: Path to an HTML template file.
            **context: Context variables for the template.

        Returns:
            Rendered HTML string, or an empty string if no template is provided.
        """
        loader, cache_key = self._resolve_html_loader(inline=inline, file=file)
        return self._render(loader, cache_key, **context)

    def _resolve_qss_loader(
        self, *, inline: str | None, file: Path | None
    ) -> tuple[AbstractJinjaBaseLoader | None, JinjaEnvironmentCacheKey | None]:
        """Resolve the loader and cache key for a QSS template.

        Args:
            inline: Inline QSS template string.
            file: Path to a QSS template file.

        Returns:
            Tuple of (loader, cache key), or (None, None) when no template exists.
        """
        if file is not None:
            cache_key = ("qss", "file", str(file.resolve()))
            return QSSFileLoader(file), cache_key
        if inline is not None and inline.strip():
            cache_key = ("qss", "inline", inline)
            return QSSStringLoader(inline), cache_key
        return None, None

    def _resolve_html_loader(
        self, *, inline: str | None, file: Path | None
    ) -> tuple[AbstractJinjaBaseLoader | None, JinjaEnvironmentCacheKey | None]:
        """Resolve the loader and cache key for an HTML template.

        Args:
            inline: Inline HTML template string.
            file: Path to an HTML template file.

        Returns:
            Tuple of (loader, cache key), or (None, None) when no template exists.
        """
        if file is not None:
            cache_key = ("html", "file", str(file.resolve()))
            return HTMLFileLoader(file), cache_key
        if inline is not None and inline.strip():
            cache_key = ("html", "inline", inline)
            return HTMLStringLoader(inline), cache_key
        return None, None

    def _render(
        self,
        loader: AbstractJinjaBaseLoader | None,
        cache_key: JinjaEnvironmentCacheKey | None,
        **context: object,
    ) -> str:
        """Render a template using the supplied loader.

        Args:
            loader: Template loader, or None if no template exists.
            cache_key: Cache key for environment reuse.
            **context: Template context variables.

        Returns:
            Rendered template string, or an empty string when no loader exists.
        """
        if loader is None:
            return ""
        env = self._get_env(loader, cache_key)
        tmpl = env.get_template(loader.get_template_name())
        return tmpl.render(**context)

    def _get_env(
        self,
        loader: AbstractJinjaBaseLoader,
        cache_key: JinjaEnvironmentCacheKey | None,
    ) -> Environment:
        """Get a Jinja environment for the given loader.

        Args:
            loader: Template loader to build the environment for.
            cache_key: Cache key for environment reuse.

        Returns:
            A Jinja environment configured for the loader.
        """
        if cache_key is None:
            return loader.make_env()

        # to prevent re-creation of the environment every time `render_qss` or `render_html` is called,
        # we cache the environment on this manager instance.
        cached_env = self._env_cache.get(cache_key)
        if cached_env is not None:
            return cached_env

        env = loader.make_env()
        if cache_key[1] == "file":
            env.auto_reload = True
        self._env_cache[cache_key] = env
        return env
