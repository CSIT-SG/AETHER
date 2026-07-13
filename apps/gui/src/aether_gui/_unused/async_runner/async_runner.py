from __future__ import annotations

import asyncio
import queue
import threading
from collections.abc import AsyncIterator, Callable, Iterator
from typing import TypeVar

T = TypeVar("T")
_SENTINEL = object()


class AsyncRunner:
    """
    Runs asyncio event loops in the background

    Used for slow async work such as:
    - LLM calls
    - MCP calls
    - worker related tasks

    Not used for IDA UI/database API calls
    """

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="AetherAsyncRunner",
            daemon=True,
        )
        self._thread.start()

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def submit_stream(
        self,
        agen_factory: Callable[[], AsyncIterator[T]],
        max_buffer: int = 100,
    ) -> Iterator[T]:
        if self._loop is None:
            raise RuntimeError("AsyncRunner not started")

        q: queue.Queue = queue.Queue(maxsize=max_buffer)

        async def _pump() -> None:
            try:
                async for item in agen_factory():
                    await asyncio.to_thread(q.put, item)
            except BaseException as exc:
                await asyncio.to_thread(q.put, exc)
            finally:
                await asyncio.to_thread(q.put, _SENTINEL)

        pump_future = asyncio.run_coroutine_threadsafe(_pump(), self._loop)

        def _iterate() -> Iterator[T]:
            try:
                while True:
                    item = q.get()
                    if item is _SENTINEL:
                        return
                    if isinstance(item, BaseException):
                        raise item
                    yield item
            finally:
                if not pump_future.done():
                    pump_future.cancel()

        return _iterate()

    def stop(self) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)
