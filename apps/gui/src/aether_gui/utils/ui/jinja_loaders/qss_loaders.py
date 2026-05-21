from __future__ import annotations

from pathlib import Path

from jinja2 import BaseLoader, Environment, TemplateNotFound

from .base import TemplateLoader


class QSSStringLoader(TemplateLoader):
    def __init__(self, source: str):
        self._source = source

    def make_env(self) -> Environment:
        class _Loader(BaseLoader):
            def get_source(_self, environment, template):
                return self._source, "<inline:qss>", lambda: True

        return Environment(
            loader=_Loader(),
            autoescape=False,  # QSS is never HTML
            keep_trailing_newline=True,
        )

    def get_template_name(self) -> str:
        return "<inline:qss>"


class QSSFileLoader(TemplateLoader):
    def __init__(self, path: Path):
        self._path = path

    def make_env(self) -> Environment:
        class _Loader(BaseLoader):
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
        return str(self._path)
