from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator
from typing import Any

from aether_gui.runner.base_task import BaseTask
from aether_gui.utils.ui import deserialise_call_tool_result
from aether_utils.logger import get_logger
from fastmcp_tasks import ToolTask

from .mcp_client import MCPClient

logger = get_logger("CallToolTask")

PROGRESS_LOG_INTERVAL_SECONDS = 1


class CallToolTask(BaseTask[Any]):  # type: ignore[misc]
    def __init__(self) -> None:
        super().__init__()
        self._tool_task: ToolTask | None = None

    async def run(
        self, mcp_client: MCPClient, tool_name: str, tool_args: dict[str, Any]
    ) -> AsyncIterator[Any]:
        logger.info("Starting Tool %s...", tool_name)
        self._tool_task = await mcp_client.call_fastmcp_tool_task(
            tool_name=tool_name, args=tool_args
        )
        task_id = self._tool_task.task_id[:8]
        logger.info("Tool %s started with task ID %s...", tool_name, task_id)
        started = time.monotonic()
        result = asyncio.ensure_future(self._tool_task.result())
        try:
            elapsed = 0
            while True:
                done, _ = await asyncio.wait({result}, timeout=PROGRESS_LOG_INTERVAL_SECONDS)
                if done:
                    break
                elapsed += PROGRESS_LOG_INTERVAL_SECONDS
                print(
                    f"\r[aether.CallToolTask] INFO: {tool_name} task {task_id}...: {elapsed}s elapsed",
                    end="",
                    flush=True,
                )
            final = await result
            if final.is_error:
                raise RuntimeError(deserialise_call_tool_result(final))
            yield final
        finally:
            ok = result.done() and not result.cancelled() and result.exception() is None
            verb = "finished in" if ok else "stopped after"
            print(
                f"\r[aether.CallToolTask] INFO: {tool_name} task {task_id}...: {verb} {time.monotonic() - started:.1f}s\n"
            )
            if not result.done():
                result.cancel()
            self._tool_task = None

    async def close(self) -> None:
        if self._tool_task is not None:
            with contextlib.suppress(Exception):
                await self._tool_task.cancel()
            self._tool_task = None
