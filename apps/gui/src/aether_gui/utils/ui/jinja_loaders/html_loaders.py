from __future__ import annotations

from pathlib import Path

from jinja2 import BaseLoader, Environment, TemplateNotFound, select_autoescape

from .base import TemplateLoader


class HTMLStringLoader(TemplateLoader):
    def __init__(self, source: str):
        self._source = source

    def make_env(self) -> Environment:
        class _Loader(BaseLoader):
            def get_source(_self, environment, template):
                return self._source, "<inline:html>", lambda: True

        return Environment(
            loader=_Loader(),
            autoescape=select_autoescape(["html"]),  # XSS-safe by default
            keep_trailing_newline=True,
            trim_blocks=True,  # cleaner HTML output
            lstrip_blocks=True,
        )

    def get_template_name(self) -> str:
        return "<inline:html>"


class HTMLFileLoader(TemplateLoader):
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
            autoescape=select_autoescape(["html"]),
            keep_trailing_newline=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def get_template_name(self) -> str:
        return str(self._path)
