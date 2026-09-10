from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from typing import Any

from aether_gui.runner.base_task import BaseTask
from fastmcp_tasks import ToolTask

from .mcp_client import MCPClient


class CallToolTask(BaseTask[Any]):  # type: ignore[misc]
    def __init__(self) -> None:
        super().__init__()
        self._tool_task: ToolTask | None = None

    async def run(
        self, mcp_client: MCPClient, tool_name: str, tool_args: dict[str, Any]
    ) -> AsyncIterator[Any]:
        self._tool_task = await mcp_client.call_fastmcp_tool_task(
            tool_name=tool_name, args=tool_args
        )
        try:
            yield await self._tool_task.result()
        finally:
            self._tool_task = None

    async def close(self) -> None:
        if self._tool_task is not None:
            with contextlib.suppress(Exception):
                await self._tool_task.cancel()
            self._tool_task = None
