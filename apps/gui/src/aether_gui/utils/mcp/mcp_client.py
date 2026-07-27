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
        self.logger = get_logger("MCPClient")

    async def connect(self) -> None:
        """Open the MCP server connection."""
        if self._connected:
            return

        transport = StreamableHttpTransport(url=self.mcp_url)
        self._client = Client(transport, timeout=None)

        try:
            await self._client.__aenter__()  # type: ignore[no-untyped-call]
            self._connected = self._client.is_connected()
            self.logger.info(f"Connected to MCP server at {self.mcp_url}")
        except Exception as e:
            self._client = None
            raise Exception("Unable to connect to MCP server") from e

    async def close(self) -> None:
        """Close the MCP server connection."""
        if not self._connected or self._client is None:
            return

        try:
            await self._client.__aexit__(None, None, None)  # type: ignore[no-untyped-call]
        except Exception as e:
            self.logger.warning(f"Error closing MCP client: {e}")
        finally:
            self._client = None
            self._connected = False
            self.logger.info("Disconnected from MCP server")

    async def list_tools(self) -> list[Tool]:
        if not self._connected:
            await self.connect()
        assert self._client is not None
        try:
            return await self._client.list_tools()
        except Exception as e:
            self.logger.error(f"Failed to list tools: {e}")
            raise

    async def call_tool(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
    ) -> AsyncIterator[CallToolResult]:
        """Connects, runs the tool, and automatically closes the connection when done."""
        if not self._connected:
            await self.connect()

        assert self._client is not None
        try:
            arguments = {**(args or {})}
            yield await self._client.call_tool(tool_name, arguments=arguments)
        except Exception as e:
            self.logger.error(f"Tool call '{tool_name}' failed: {e}")
