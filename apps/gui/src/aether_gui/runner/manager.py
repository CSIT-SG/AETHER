from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from concurrent.futures import Future
from typing import Any

from .base_task import BaseTask
from .types import TaskHandle

_SENTINEL = object()


class WorkerManager[T]:
    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self._ready.wait()
        self._tasks: dict[str, Future] = {}

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._ready.set()
        self._loop.run_forever()

    def submit(self, task: BaseTask[T], *args: Any, **kwargs: Any) -> TaskHandle:
        handle = TaskHandle(task_id=task.id)
        future = asyncio.run_coroutine_threadsafe(
            self._drive(handle, task, *args, **kwargs),
            self._loop,
        )
        self._tasks[task.id] = future
        return handle

    async def _drive(
        self,
        handle: TaskHandle,
        task: BaseTask[T],
        *args: Any,
        **kwargs: Any,
    ) -> None:
        try:
            async for item in task.run(*args, **kwargs):
                handle.results.put(item)
        except BaseException as exc:
            handle.error = exc
        finally:
            await task.close()
            handle.results.put(_SENTINEL)
            handle.done.set()
            self._tasks.pop(handle.task_id, None)

    def consume(
        self,
        handle: TaskHandle,
        on_event: Callable[[T], None],
        on_error: Callable[[BaseException], None] | None = None,
        on_done: Callable[[], None] | None = None,
    ) -> None:
        """Consume events on a worker thread. Returns immediately.

        Callbacks fire on the consumer thread — caller marshals to UI thread inside
        the callback if needed.
        """

        def _consume() -> None:
            try:
                while True:
                    item = handle.results.get()
                    if item is _SENTINEL:
                        if handle.error is not None and on_error:
                            on_error(handle.error)
                        break
                    on_event(item)
            except BaseException as e:
                if on_error:
                    on_error(e)
            finally:
                if on_done:
                    on_done()

        threading.Thread(
            target=_consume,
            daemon=True,
            name=f"consumer-{handle.task_id[:8]}",
        ).start()

    def cancel(self, task_id: str) -> bool:
        future = self._tasks.get(task_id)
        if future is None or future.done():
            return False
        return future.cancel()

    def shutdown(self) -> None:
        for future in list(self._tasks.values()):
            if not future.done():
                future.cancel()
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)
