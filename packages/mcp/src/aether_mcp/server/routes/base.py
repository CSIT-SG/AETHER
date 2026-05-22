from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import httpx
from mcp.server import Server
from mcp.types import (
    CallToolResult,
    TextContent,
)
from openai import AsyncOpenAI

from ..services import PromptCommand, ResourceCommand, ToolCommand


@dataclass
class IDAContext:
    """IDA database state — what the binary looks like."""

    idb_path: str
    segment_map: dict[str, Any] = field(default_factory=dict)


@dataclass
class ServerContext:
    """Server infrastructure — how the server talks to the outside world.

    For example, the server may want to spawn a subagent that calls back into the server's own API routes.
    """

    ida: IDAContext
    http_client: httpx.AsyncClient | None = None
    openai_client: AsyncOpenAI | None = None


class AbstractMCPRoute(ABC):
    def __init__(self, ctx: ServerContext) -> None:
        self._ctx = ctx

    @property
    def ctx(self) -> ServerContext:
        """Expose server context to route implementations, but keep it read-only."""
        return self._ctx

    @ctx.setter
    def ctx(self, _value: ServerContext) -> None:
        raise AttributeError("ServerContext is read-only and cannot be modified.")

    @property
    @abstractmethod
    def prefix(self) -> str:
        """
        Short namespace prefix for this route.

        For exanple, if the prefix is "weather", then the generated route for a tool command named "get_forecast" would be ("/weather_get_forecast").
        """

    def _name(self, local: str) -> str:
        """Return ``"<prefix>_<local>"``."""
        return f"{self.prefix}_{local}"

    # Capabilities

    @property
    def tools(self) -> Sequence[ToolCommand]:
        """Tools exposed by this route.  Override to add tools."""
        return []

    @property
    def resources(self) -> Sequence[ResourceCommand]:
        """Resources exposed by this route.  Override to add resources."""
        return []

    @property
    def prompts(self) -> Sequence[PromptCommand]:
        """Prompts exposed by this route.  Override to add prompts."""
        return []

    # Lifecycle hooks

    def on_startup(self) -> None:
        """
        Called once before :meth:`register`.

        Use for one-time setup: opening DB connections, loading config,
        warming caches, etc.  Runs synchronously; use an async subclass
        hook if you need ``await``.
        """
        return None

    def on_shutdown(self) -> None:
        """
        Called once when the server is stopping.

        Use for cleanup: closing connections, flushing buffers, etc.
        """
        return None

    # Error helpers

    @staticmethod
    def error_result(message: str) -> CallToolResult:
        """Return a tool-error result."""
        return CallToolResult(
            isError=True,
            content=[TextContent(type="text", text=message)],
        )

    @staticmethod
    def ok_result(text: str) -> CallToolResult:
        """Return a tool success result."""
        return CallToolResult(content=[TextContent(type="text", text=text)])

    def register(self, server: Server) -> None:
        """
        Attach all tools, resources, and prompts to *server*.

        Called once at startup by the server factory.  Delegates to the
        three private helpers so each concern is isolated.

        Args:
            server: The running :class:`mcp.server.Server` instance.
        """
        self.on_startup()
        self._register_tools(server)
        self._register_resources(server)
        self._register_prompts(server)

    # TODO: implement register

    def _register_tools(self, server: Server) -> None:
        raise NotImplementedError("Tool registration not implemented.")

    def _register_resources(self, server: Server) -> None:
        raise NotImplementedError("Resource registration not implemented.")

    def _register_prompts(self, server: Server) -> None:
        raise NotImplementedError("Prompt registration not implemented.")
