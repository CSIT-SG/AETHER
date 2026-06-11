from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator
from typing import Any


class BaseCapability(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    async def execute(self, **kwargs: Any) -> AsyncGenerator[Any, None]:
        raise NotImplementedError
