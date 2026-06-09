from abc import ABC, abstractmethod
from typing import Any

from mcp.types import GetPromptResult, Prompt


class BasePrompt(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def description(self) -> str: ...

    def to_prompt(self) -> Prompt:
        return Prompt(
            name=self.name,
            description=self.description,
        )

    @abstractmethod
    async def get(self, **kwargs: Any) -> GetPromptResult:
        raise NotImplementedError
