from __future__ import annotations

from abc import ABC, abstractmethod

from jinja2 import Environment


class TemplateLoader(ABC):
    """Abstract base class for Jinja template loaders used by styled components.

    Implementations of this interface provide a configured :class:`jinja2.Environment`
    and a unique template name for the environment. Subclasses are responsible for
    creating an environment appropriate for the template source (string or file).

    Methods
    -------
    make_env
        Create and return a configured :class:`jinja2.Environment` instance.

    get_template_name
        Return a stable, unique name for the template served by the environment.
    """

    @abstractmethod
    def make_env(self) -> Environment:
        """Create a Jinja Environment with this loader."""
        raise NotImplementedError

    @abstractmethod
    def get_template_name(self) -> str:
        """Return a unique name for this template."""
        raise NotImplementedError
