from __future__ import annotations

from pathlib import Path

from jinja2 import BaseLoader, Environment, TemplateNotFound

from .base import TemplateLoader


class QSSStringLoader(TemplateLoader):
    """Load QSS (Qt stylesheet) templates from an in-memory string.

    The returned :class:`jinja2.Environment` is configured for non-HTML
    template rendering (autoescape disabled). This is intended for styling
    templates where HTML escaping is inappropriate.

    Args:
        source: The QSS template source string.
    """

    def __init__(self, source: str):
        self._source = source

    def make_env(self) -> Environment:
        class _Loader(BaseLoader):
            """Internal Jinja2 loader that returns the provided QSS string.

            Implements the :meth:`get_source` method required by Jinja2 loaders.
            """

            def get_source(_self, environment, template):
                return self._source, "<inline:qss>", lambda: True

        return Environment(
            loader=_Loader(),
            autoescape=False,  # QSS is never HTML
            keep_trailing_newline=True,
        )

    def get_template_name(self) -> str:
        """Return the synthetic template name for inline QSS templates.

        Returns:
            A stable identifier used as the template name within the environment.
        """

        return "<inline:qss>"


class QSSFileLoader(TemplateLoader):
    """Load QSS templates from a file on disk.

    This loader reads the template file and provides a Jinja2 environment
    configured for QSS rendering (autoescape disabled). The template name is
    the file path and freshness is determined by the file's modification time.

    Args:
        path: Path to the QSS template file.
    """

    def __init__(self, path: Path):
        self._path = path

    def make_env(self) -> Environment:
        class _Loader(BaseLoader):
            """Internal Jinja2 loader that reads the QSS template from disk.

            Returns the file contents, the file path as template name, and a
            callable used by Jinja2 to check whether the template is up-to-date.
            """

            def get_source(_self, environment, template):
                if not self._path.exists():
                    raise TemplateNotFound(str(self._path))
                source = self._path.read_text(encoding="utf-8")
                mtime = self._path.stat().st_mtime
                return source, str(self._path), lambda: self._path.stat().st_mtime == mtime

        return Environment(
            loader=_Loader(),
            autoescape=False,
            keep_trailing_newline=True,
        )

    def get_template_name(self) -> str:
        """Return the filesystem path used as the template name.

        Returns:
            The string representation of the template file path.
        """

        return str(self._path)
