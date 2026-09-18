from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class JinjaPluginProtocol(Protocol):
    def styles(self) -> str | None:
        """Return an inline QSS template string.

        Returns:
            Inline QSS template or ``None`` when not provided.
        """
        ...

    def style_file(self) -> Path | None:
        """Return a path to a QSS template file.

        Returns:
            Path to a QSS template file or ``None`` when not provided.
        """
        ...

    def template(self) -> str | None:
        """Return an inline HTML template string.

        Returns:
            Inline HTML template or ``None`` when not provided.
        """
        ...

    def template_file(self) -> Path | None:
        """Return a path to an HTML template file.

        Returns:
            Path to an HTML template file or ``None`` when not provided.
        """
        ...
