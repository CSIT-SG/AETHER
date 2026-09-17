from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator
from typing import Any

from aether_gui.runner.base_task import BaseTask
from aether_utils.logger import get_logger
from fastmcp_tasks import ToolTask

from .mcp_client import MCPClient

logger = get_logger("CallToolTask")

PROGRESS_LOG_INTERVAL_SECONDS = 10


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
        task_id = self._tool_task.task_id[:8]
        started = time.monotonic()
        result = asyncio.ensure_future(self._tool_task.result())
        try:
            elapsed = 0
            while True:
                done, _ = await asyncio.wait({result}, timeout=PROGRESS_LOG_INTERVAL_SECONDS)
                if done:
                    break
                elapsed += PROGRESS_LOG_INTERVAL_SECONDS
                logger.info("%s task %s...: %ds elapsed", tool_name, task_id, elapsed)
            yield await result
        finally:
            ok = result.done() and not result.cancelled() and result.exception() is None
            verb = "finished in" if ok else "stopped after"
            logger.info(
                "%s task %s...: %s %.1fs", tool_name, task_id, verb, time.monotonic() - started
            )
            if not result.done():
                result.cancel()
            self._tool_task = None

    async def close(self) -> None:
        if self._tool_task is not None:
            with contextlib.suppress(Exception):
                await self._tool_task.cancel()
            self._tool_task = None
