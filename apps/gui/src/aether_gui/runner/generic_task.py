from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from typing import Any

from .base_task import BaseTask


class GenericTask(BaseTask):
    def __init__(
        self,
        name: str | None = None,
    ) -> None:
        super().__init__(name=name)

    async def run(self, fn: Callable[..., AsyncIterator[Any]], **kwargs: Any) -> AsyncIterator[Any]:
        async for event in fn(**kwargs):
            yield event

    async def close(self) -> None:
        pass
