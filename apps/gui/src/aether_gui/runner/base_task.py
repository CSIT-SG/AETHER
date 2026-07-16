from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import Any, TypeVar
from uuid import uuid4

T = TypeVar("T")


class BaseTask[T](ABC):
    """Abstract Base Class for asynchronous tasks managed manually by a Worker Manager."""

    def __init__(self) -> None:
        self.id: str = str(uuid4())
        self.name: str = self.__class__.__name__
        self.is_running: bool = False
        self.has_failed: bool = False

    @abstractmethod
    def run(self, *args: Any, **kwargs: Any) -> AsyncIterator[T]:
        """Asynchronously execute the core workload.

        Subtasks implement their own run logic that carries out heavy async workload that might block IDA thread.
        """

    @abstractmethod
    async def close(self) -> None:
        """Asynchronously release resources (e.g., closing async client connections)."""
        ...
