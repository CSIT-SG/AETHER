from __future__ import annotations

from pathlib import Path

from jinja2 import BaseLoader, Environment, TemplateNotFound, select_autoescape

from .abstract_jinja_base_loader import AbstractJinjaBaseLoader


class HTMLStringLoader(AbstractJinjaBaseLoader):
    """Load HTML templates from an in-memory string.

    This loader builds a :class:`jinja2.Environment` that serves a single
    HTML template provided as a string. The environment is configured with
    sensible defaults for HTML generation (autoescaping, trimming blocks).

    Args:
        source: The HTML template source string.
    """

    def __init__(self, source: str):
        """Initialize the loader with an inline HTML template.

        Args:
            source: HTML template source string.
        """
        self._source = source

    def make_env(self) -> Environment:
        """Create a Jinja environment for inline HTML templates.

        Returns:
            A configured Jinja environment.
        """

        class _Loader(BaseLoader):
            """Internal Jinja2 loader that returns the provided HTML string.

            The loader implements :meth:`get_source` expected by Jinja2's
            loader protocol.
            """

            def get_source(_self, environment, template):
                """Return the inline template source for Jinja.

                Args:
                    environment: Jinja environment requesting the source.
                    template: Template name being requested.

                Returns:
                    Tuple of (source, template name, uptodate callable).
                """
                return self._source, "<inline:html>", lambda: True

        return Environment(
            loader=_Loader(),
            autoescape=select_autoescape(["html"]),  # XSS-safe by default
            keep_trailing_newline=True,
            trim_blocks=True,  # cleaner HTML output
            lstrip_blocks=True,
        )

    def get_template_name(self) -> str:
        """Return the synthetic template name for inline HTML templates.

        Returns:
            A stable identifier used as the template name within the environment.
        """

        return "<inline:html>"


class HTMLFileLoader(AbstractJinjaBaseLoader):
    """Load HTML templates from a file on disk.

    This loader builds a :class:`jinja2.Environment` that reads the template
    from the provided filesystem path. The environment will report the file
    path as the template name and provides a callable that Jinja2 uses to
    determine template freshness.

    Args:
        path: Path to the HTML template file.
    """

    def __init__(self, path: Path):
        """Initialize the loader with a template file path.

        Args:
            path: Path to the HTML template file.
        """
        self._path = path

    def make_env(self) -> Environment:
        """Create a Jinja environment for file-based HTML templates.

        Returns:
            A configured Jinja environment.
        """

        class _Loader(BaseLoader):
            """Internal Jinja2 loader that reads the template from disk.

            The loader returns the file contents, the file path as the template
            name, and a callable that compares modification times to determine
            whether the template is up-to-date.
            """

            def get_source(_self, environment, template):
                """Return the file template source for Jinja.

                Args:
                    environment: Jinja environment requesting the source.
                    template: Template name being requested.

                Returns:
                    Tuple of (source, template name, uptodate callable).

                Raises:
                    TemplateNotFound: If the template file does not exist.
                """
                if not self._path.exists():
                    raise TemplateNotFound(str(self._path))
                source = self._path.read_text(encoding="utf-8")
                mtime = self._path.stat().st_mtime
                return source, str(self._path), lambda: self._path.stat().st_mtime == mtime

        return Environment(
            loader=_Loader(),
            autoescape=select_autoescape(["html"]),
            keep_trailing_newline=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def get_template_name(self) -> str:
        """Return the filesystem path used as the template name.

        Returns:
            The string representation of the template file path.
        """

        return str(self._path)
