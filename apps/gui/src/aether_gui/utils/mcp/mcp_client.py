from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from aether_utils.config import get_config
from aether_utils.logger import get_logger
from fastmcp import Client
from fastmcp.client.client import CallToolResult
from fastmcp.client.transports import StreamableHttpTransport

from mcp.types import Tool

config = get_config()


class MCPClient:
    """A fully asynchronous MCP client that connects, executes tools,
    and handles automatic cleanup after a tool call.
    """

    def __init__(self) -> None:
        self.mcp_url = config.mcp_url
        self._client: Client[StreamableHttpTransport] | None = None
        self._connected: bool = False
        self._tool_cache: list[Tool] | None = None
        self.logger = get_logger("MCPClient")

    async def connect(self) -> None:
        """Open the MCP server connection."""
        if self._connected:
            return

        transport = StreamableHttpTransport(url=self.mcp_url)
        self._client = Client(transport)

        try:
            await self._client.__aenter__()
            self._connected = True
            self.logger.info(f"Connected to MCP server at {self.mcp_url}")
        except Exception:
            self._client = None
            raise

    async def close(self) -> None:
        """Close the MCP server connection."""
        if not self._connected or self._client is None:
            return

        try:
            await self._client.__aexit__(None, None, None)
        except Exception as e:
            self.logger.warning(f"Error closing MCP client: {e}")
        finally:
            self._client = None
            self._connected = False
            self._tool_cache = None
            self.logger.info("Disconnected from MCP server")

    async def _ensure_connected(self) -> None:
        if not self._connected:
            await self.connect()

    async def call_tool(
        self,
        rpc_id: str,
        tool_name: str,
        args: dict[str, Any] | None = None,
    ) -> AsyncIterator[CallToolResult]:
        """Connects, runs the tool, and automatically closes the connection when done."""
        await self._ensure_connected()
        assert self._client is not None
        try:
            arguments = {"rpc_id": rpc_id, **(args or {})}
            yield await self._client.call_tool(tool_name, arguments=arguments)
        except Exception as e:
            self.logger.error(f"Tool call '{tool_name}' failed: {e}")
