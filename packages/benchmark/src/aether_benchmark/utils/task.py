import asyncio
from abc import ABC, abstractmethod
from collections.abc import Generator
from typing import Any, Self


class Task[**P, T](ABC):
    @abstractmethod
    async def start(self, *args: P.args, **kwargs: P.kwargs) -> T:
        """Run the task with the given arguments."""
        ...

    @abstractmethod
    async def cancel(self) -> None:
        """Cancel the task."""
        ...


class Run[**P, T]:
    """A functor that wraps a `Task[P, T]` type, making it callable to start execution.

        Usage:
    ```python
            run = Run(MyTask)   # wrap MyTask in a functor (nothing runs yet)
            run(arg1, arg2)     # __call__: starts the task, returns self
            await run           # __await__: wait for the task to complete
    ```

        Or scoped to a `with` block, which cancels the task on exit:
    ```python
            async with Run(MyTask)(arg1, arg2) as run:
                ...
    ```
    """

    def __init__(self, task: type[Task[P, T]]) -> None:
        self._task: Task[P, T] = task()
        self._future: asyncio.Task[T] | None = None

    async def _run(self, *args: P.args, **kwargs: P.kwargs) -> T:
        try:
            return await self._task.start(*args, **kwargs)
        finally:
            await self._task.cancel()

    def __call__(self, *args: P.args, **kwargs: P.kwargs) -> Self:
        """Start the task with the given arguments."""
        self._future = asyncio.create_task(self._run(*args, **kwargs))
        return self

    def __await__(self) -> Generator[Any, None, T]:
        if self._future is None:
            raise RuntimeError("Run must be called before it can be awaited")
        return self._future.__await__()

    async def __aenter__(self) -> Self:
        if self._future is None:
            raise RuntimeError("Run must be called before entering the context")
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        assert self._future is not None, "Run must be called before exiting the context"
        self._future.cancel()
        try:
            await self._future
        except asyncio.CancelledError:
            pass
        return False
