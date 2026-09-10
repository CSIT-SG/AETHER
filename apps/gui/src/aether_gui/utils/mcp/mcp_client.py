from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from typing import Any

from aether_utils.config import get_config
from aether_utils.logger import get_logger
from fastmcp import Client
from fastmcp.client.client import CallToolResult
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
        self._active_tasks: dict[str, ToolTask] = {}
        self.logger = get_logger("MCPClient")

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

    async def cancel_task(self, task_id: str) -> None:
        task = self._active_tasks.pop(task_id, None)
        if task is not None:
            with contextlib.suppress(Exception):
                await task.cancel()

    async def close(self) -> None:
        """Close the MCP server connection."""
        if not self.is_connected() or self._client is None:
            return

        for task_id in list(self._active_tasks.keys()):
            await self.cancel_task(task_id)

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

    async def call_tool(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        task_id: str | None = None,
    ) -> AsyncIterator[CallToolResult]:
        """Connects, runs the tool, and automatically closes the connection when done."""
        try:
            if not self.is_connected():
                await self.connect()

            assert self._client is not None
            arguments = {**(args or {})}

            task: ToolTask | None = None
            key: str | None = None
            try:
                task = await call_tool_task(
                    self._client, tool_name, arguments=arguments, raise_on_error=False
                )
                key = task_id or task.task_id
                self._active_tasks[key] = task
                result = await task.result()
                yield result
            finally:
                if key is not None:
                    self._active_tasks.pop(key, None)
        except Exception as e:
            self.logger.error(f"Tool call '{tool_name}' failed: {e}")
            raise
