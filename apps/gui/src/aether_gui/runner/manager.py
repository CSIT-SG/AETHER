from __future__ import annotations

import asyncio
import contextlib
import threading
from collections.abc import Callable
from concurrent.futures import Future
from typing import Any

from .base_task import BaseTask
from .types import SENTINEL, TaskHandle


class WorkerManager:
    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self._ready.wait()
        self._tasks: dict[str, tuple[BaseTask[Any], Future[None]]] = {}

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._ready.set()
        self._loop.run_forever()

    def submit[T](self, task: BaseTask[T], *args: Any, **kwargs: Any) -> TaskHandle[T]:
        handle = TaskHandle[T](task_id=task.id)
        future = asyncio.run_coroutine_threadsafe(
            self._drive(handle, task, *args, **kwargs),
            self._loop,
        )
        self._tasks[task.id] = (task, future)
        return handle

    async def _drive[T](
        self,
        handle: TaskHandle[T],
        task: BaseTask[T],
        *args: Any,
        **kwargs: Any,
    ) -> None:
        task.is_running = True
        try:
            async for item in task.run(*args, **kwargs):
                handle.results.put(item)
        except BaseException as exc:
            task.has_failed = True
            handle.error = exc
        finally:
            task.is_running = False
            with contextlib.suppress(Exception):
                await task.close()
            handle.results.put(SENTINEL)
            handle.done.set()
            self._tasks.pop(handle.task_id, None)

    def consume[T](
        self,
        handle: TaskHandle[T],
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
                while (item := handle.results.get()) is not SENTINEL:
                    on_event(item)
            except BaseException as e:
                if on_error:
                    on_error(e)
            else:
                if handle.error is not None and on_error:
                    on_error(handle.error)
            finally:
                if on_done:
                    on_done()

        threading.Thread(
            target=_consume,
            daemon=True,
            name=f"consumer-{handle.task_id}",
        ).start()

    def cancel(self, task_id: str) -> None:
        task_data = self._tasks.get(task_id)
        if task_data is None:
            return

        task, future = task_data
        if not task.is_running or task.has_failed:
            return

        if future.done():
            return

        with contextlib.suppress(Exception):
            asyncio.run_coroutine_threadsafe(task.close(), self._loop).result()
        future.cancel()

    def shutdown(self) -> None:
        for task, future in list(self._tasks.values()):
            if task.is_running and not task.has_failed:
                with contextlib.suppress(Exception):
                    asyncio.run_coroutine_threadsafe(task.close(), self._loop).result()

            if not future.done():
                future.cancel()
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)
