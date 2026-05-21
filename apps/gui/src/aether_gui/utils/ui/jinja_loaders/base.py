from __future__ import annotations

from abc import ABC, abstractmethod

from jinja2 import Environment


class TemplateLoader(ABC):
    """Common interface for all Jinja loaders used in styled components."""

    @abstractmethod
    def make_env(self) -> Environment:
        """Create a Jinja Environment with this loader."""
        raise NotImplementedError

    @abstractmethod
    def get_template_name(self) -> str:
        """Return a unique name for this template."""
        raise NotImplementedError
