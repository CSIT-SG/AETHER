# NOTE: FAKE WORKER MANAGER
from __future__ import annotations

from collections.abc import AsyncIterator

from ..llm import LLMResponse
from .worker_runtime import WorkerRuntime
from .worker_types import WorkerTask


class WorkerManager:
    """Worker Manager handles both connections with MCPClient and LLMCLient"""

    def __init__(self, worker_runtime: WorkerRuntime) -> None:
        self._worker_runtime = worker_runtime

    async def submit(self, task: WorkerTask) -> AsyncIterator[LLMResponse]:
        async for response in self._worker_runtime.run_task(task):
            yield response

    async def close(self) -> None:
        await self._worker_runtime.close()
