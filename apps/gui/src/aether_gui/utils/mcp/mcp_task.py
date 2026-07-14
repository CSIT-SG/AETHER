from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from aether_gui.runner import BaseTask
from fastmcp.client.client import CallToolResult

from .mcp_client import MCPClient


class MCPTask(BaseTask):
    def __init__(
        self,
        rpc_id: str,
        tool_name: str,
        args: dict[str, Any],
        name: str | None = None,
    ) -> None:
        super().__init__(name=name)
        self.rpc_id = rpc_id
        self.tool_name = tool_name
        self.args = args
        self._manager = MCPClient()

    async def run(self) -> AsyncIterator[CallToolResult]:
        async for event in self._manager.call_tool(
            rpc_id=self.rpc_id,
            tool_name=self.tool_name,
            args=self.args,
        ):
            yield event

    async def close(self) -> None:
        await self._manager.close()
