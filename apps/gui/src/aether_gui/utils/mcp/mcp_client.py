from __future__ import annotations

from typing import Any

from aether_gui.utils.mcp.types import LogSubscription, ServerLogListener
from aether_utils.config import get_config
from aether_utils.logger import get_logger
from fastmcp import Client
from fastmcp.client.client import CallToolResult
from fastmcp.client.logging import LogMessage
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp_tasks import ToolTask, call_tool_task
from mcp_types import Tool

config = get_config()


class MCPClient:
    """A fully asynchronous MCP client that connects, executes tools,
    and handles automatic cleanup after a tool call.
    """

    def __init__(self) -> None:
        self.mcp_url = config.mcp_url
        self._client: Client[StreamableHttpTransport] | None = None
        self.logger = get_logger("MCPClient")
        self._log_listeners: set[ServerLogListener] = set()

    def subscribe_logs(self, listener: ServerLogListener) -> LogSubscription:
        """Register async listener for server logs"""
        self._log_listeners.add(listener)
        return LogSubscription(self, listener)

    def unsubscribe_logs(self, listener: ServerLogListener) -> None:
        """Deregister a previously-subscribed listener"""
        self._log_listeners.discard(listener)

    async def _handle_log(self, message: LogMessage) -> None:
        """Sends server logs to all listeners."""
        if not self._log_listeners:
            return
        text = str(message.data)
        for listener in list(self._log_listeners):
            try:
                await listener(text)
            except Exception:
                self.logger.exception("Server log listener failed")

    def is_connected(self) -> bool:
        """Check if the client is connected to the MCP server."""
        return self._client is not None and self._client.is_connected()

    async def connect(self) -> None:
        """Open the MCP server connection."""
        if self.is_connected():
            return

        transport = StreamableHttpTransport(url=self.mcp_url)
        self._client = Client(transport, log_handler=self._handle_log)

        try:
            await self._client.__aenter__()  # type: ignore[no-untyped-call]
            self.logger.info(f"Connected to MCP server at {self.mcp_url}")
        except Exception as e:
            self._client = None
            raise Exception("Unable to connect to MCP server") from e

    async def close(self) -> None:
        """Close the MCP server connection."""
        if not self.is_connected() or self._client is None:
            return

        try:
            await self._client.__aexit__(None, None, None)  # type: ignore[no-untyped-call]
        except Exception as e:
            self.logger.warning(f"Error closing MCP client: {e}")
        finally:
            self._client = None
            self.logger.info("Disconnected from MCP server")

    async def list_tools(self) -> list[Tool]:
        if not self.is_connected():
            await self.connect()
        assert self._client is not None
        try:
            return await self._client.list_tools()
        except Exception as e:
            self.logger.error(f"Failed to list tools: {e}")
            raise

    async def call_fastmcp_tool_task(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
    ) -> ToolTask:
        if not self.is_connected():
            await self.connect()

        assert self._client is not None
        arguments = {**(args or {})}
        return await call_tool_task(
            self._client, tool_name, arguments=arguments, raise_on_error=False
        )
