from __future__ import annotations

import asyncio
from typing import Any

from aether_gui.utils.mcp.types import LogSubscription, ServerLogListener, ServerProgressMessage
from aether_utils.config import get_config
from aether_utils.logger import get_logger
from fastmcp import Client
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

    def is_connected(self) -> bool:
        """Check if the client is connected to the MCP server."""
        return self._client is not None and self._client.is_connected()

    async def connect(self) -> None:
        """Open the MCP server connection."""
        if self.is_connected():
            return

        transport = StreamableHttpTransport(url=self.mcp_url)
        self._client = Client(transport)

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

    def _broadcast_progress(
        self, message: str | None, progress: float = 0, total: float | None = None
    ) -> None:
        """Fan a subtool trace out to every subscribed listener."""
        if not self._log_listeners:
            return
        event = ServerProgressMessage(message=message, progress=progress, total=total)
        for listener in list(self._log_listeners):
            try:
                coro = listener(event)
            except Exception:
                self.logger.exception("Server progress listener failed")
                continue
            asyncio.ensure_future(coro)

    async def poll_subtool_traces(self, task: ToolTask) -> None:
        """Poll `task.status()` and broadcast new `status_message` traces."""
        terminal = {"completed", "failed", "cancelled"}
        last_message: str | None = None
        default_interval = 0.5

        while True:
            try:
                status = await task.status()
            except Exception:
                self.logger.exception("Subtool poll failed")
                return

            if status.status_message and status.status_message != last_message:
                last_message = status.status_message
                self._broadcast_progress(status.status_message)

            if status.status in terminal:
                return

            interval = (
                status.poll_interval_ms / 1000
                if status.poll_interval_ms is not None and status.poll_interval_ms > 0
                else default_interval
            )
            await asyncio.sleep(interval)
