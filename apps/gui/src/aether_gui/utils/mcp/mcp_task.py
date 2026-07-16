from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from aether_gui.runner.base_task import BaseTask

from .mcp_client import MCPClient


class CallToolTask(BaseTask[Any]):
    def __init__(self) -> None:
        super().__init__()

    async def run(self, mcp_client: MCPClient, tool_name: str, **kwargs: Any) -> AsyncIterator[Any]:
        async for event in mcp_client.call_tool(tool_name=tool_name, **kwargs):
            yield event

    async def close(self) -> None:
        pass
