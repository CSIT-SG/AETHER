from __future__ import annotations

import asyncio
import concurrent.futures
import threading
from typing import Any, TypeVar
from uuid import uuid4

from .base_task import BaseTask
from .types import TaskHandle, TaskStatus

T = TypeVar("T")
_SENTINEL = object()


class WorkerManager[T]:
    """Manages async tasks. Each submitted task runs concurrently, streaming events."""

    def __init__(self, max_concurrent: int = 10) -> None:
        self._max_concurrent = max_concurrent
        self._sem: asyncio.Semaphore | None = None
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="WorkerManagerAsyncRunner",
            daemon=True,
        )
        self._thread.start()

        # Track active tasks: task_id -> (task, handle, pump_future)
        self.registry: dict[
            str, tuple[BaseTask[Any], TaskHandle, concurrent.futures.Future[Any]]
        ] = {}

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        # Initialize the semaphore inside the event loop's native thread context
        self._sem = asyncio.Semaphore(self._max_concurrent)
        self._loop.run_forever()

    def submit(self, task: BaseTask[T], *args: Any, **kwargs: Any) -> TaskHandle:
        """Submit an async iterator factory. Returns a handle for consuming events."""
        task_id = str(uuid4())
        task.id = task_id
        handle = TaskHandle(task_id=task_id)

        pump_future = asyncio.run_coroutine_threadsafe(
            self._run(handle, task, *args, **kwargs), self._loop
        )

        self.registry[task_id] = (task, handle, pump_future)

        return handle

    async def _run(
        self,
        handle: TaskHandle,
        task: BaseTask[T],
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """Execute the task, pushing events into its queue."""
        while self._sem is None:
            await asyncio.sleep(0.001)

        async with self._sem:
            handle.status = TaskStatus.RUNNING
            try:
                async_stream = await task.run(*args, **kwargs)
                task.is_running = True
                async for item in async_stream:
                    await asyncio.to_thread(handle._queue.put, item)
                handle.status = TaskStatus.COMPLETED
            except asyncio.CancelledError:
                task.has_failed = True
                handle.status = TaskStatus.CANCELLED
                raise
            except BaseException as exc:
                handle.status = TaskStatus.FAILED
                handle.error = exc
                await asyncio.to_thread(handle._queue.put, exc)
            finally:
                task.is_running = False
                await task.close()
                await asyncio.to_thread(handle._queue.put, _SENTINEL)
                handle._done.set()

    def cancel(self, task_id: str) -> bool:
        """Cancel a running task. Returns True if the task existed."""
        record = self.registry.get(task_id)
        if record is None:
            return False

        _, handle, pump_future = record
        if pump_future.done():
            return False

        pump_future.cancel()
        handle.status = TaskStatus.CANCELLED
        return True

    def get(self, task_id: str) -> TaskHandle | None:
        """Retrieve a task handle by ID."""
        record = self.registry.get(task_id)
        return record[1] if record else None

    async def shutdown(self, timeout: float = 30.0) -> None:
        """Cancel all running tasks and wait for them to finish."""
        for _, handle, pump_future in self.registry.values():
            if not pump_future.done():
                pump_future.cancel()
                handle.status = TaskStatus.CANCELLED

        self._loop.call_soon_threadsafe(self._loop.stop)
