from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from mcp.server import Server
from mcp.types import (
    CallToolResult,
    TextContent,
)
from pydantic import AnyUrl

from ..services import PromptCommand, ResourceCommand, ResourceTemplateCommand, ToolCommand

# TODO: shift this to some other utils file

@dataclass
class IDAContext:
    """IDA database state — what the binary looks like."""
    idb_path: str
    architecture: str | None = None
    bitness: int | None = None          # 32 or 64
    entry_point: int | None = None
    segment_map: list[dict[str, Any]] = field(default_factory=list)
    functions: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ServerContext:
    """Server infrastructure — per-client session state."""
    ida: IDAContext


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
    def resource_templates(self) -> Sequence[ResourceTemplateCommand]:
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

    def _register_tools(self, server: Server) -> None:
        @server.list_tools()
        async def list_tools():
            return [cmd.tool for cmd in self.tools]

        @server.call_tool()
        async def call_tool(name: str, arguments: dict):
            for cmd in self.tools:
                if cmd.tool.name == name:
                    return await cmd.handler(**arguments)

            raise ValueError(f"Unknown tool: {name}")

    def _register_resources(self, server: Server) -> None:
        @server.list_resources()
        async def list_resources():
            return [cmd.resource for cmd in self.resources]

        @server.list_resource_templates()
        async def list_resource_templates():
            return [cmd.template for cmd in self.resource_templates]

        @server.read_resource()
        async def read_resource(uri: AnyUrl):
            for cmd in self.resources:
                if cmd.resource.uri == str(uri):
                    return await cmd.handler(str(uri))
            raise ValueError(f"Unknown resource: {uri}")

    def _register_prompts(self, server: Server) -> None:
        @server.list_prompts()
        async def list_prompts():
            return [cmd.prompt for cmd in self.prompts]

        @server.get_prompt()
        async def get_prompt(name: str, arguments: dict[str, str] | None):
            for cmd in self.prompts:
                if cmd.prompt.name == name:
                    return await cmd.handler(**(arguments or {}))

            raise ValueError(f"Unknown prompt: {name}")
