from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from aether_gui.runner.base_task import BaseTask

from .mcp_client import MCPClient


class CallToolTask(BaseTask[Any]):  # type: ignore[misc]
    def __init__(self) -> None:
        super().__init__()
        self._mcp_client: MCPClient | None = None

    async def run(
        self, mcp_client: MCPClient, tool_name: str, tool_args: dict[str, Any]
    ) -> AsyncIterator[Any]:
        self._mcp_client = mcp_client
        async for event in mcp_client.call_tool(tool_name=tool_name, args=tool_args):
            yield event

    async def close(self) -> None:
        if self._mcp_client is not None:
            await self._mcp_client.close()
            self._mcp_client = None
