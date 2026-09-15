"""Merges async iterator streams."""

import asyncio
from collections.abc import AsyncGenerator, AsyncIterator
from typing import TypeVar

from .types import _SENTINEL

T = TypeVar("T")


async def merge_aiterators[T](*aiters: AsyncIterator[T]) -> AsyncGenerator[T, None]:
    """Merge multiple async iterators, yielding items as soon as any produces one."""
    queue: asyncio.Queue[T | object] = asyncio.Queue()

    async def producer(ait: AsyncIterator[T]) -> None:
        try:
            async for item in ait:
                await queue.put(item)
        finally:
            await queue.put(_SENTINEL)

    tasks: list[asyncio.Task[None]] = [asyncio.create_task(producer(ait)) for ait in aiters]
    remaining = len(tasks)
    try:
        while remaining > 0:
            item = await queue.get()
            if item is _SENTINEL:
                remaining -= 1
            else:
                yield item  # type: ignore
    finally:
        for task in tasks:
            task.cancel()
