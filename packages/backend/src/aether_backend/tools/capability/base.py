from abc import ABC, abstractmethod
from typing import Any, AsyncGenerator


class BaseCapability(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    async def execute(self, **kwargs: Any) -> AsyncGenerator[Any, None]:
        raise NotImplementedError
