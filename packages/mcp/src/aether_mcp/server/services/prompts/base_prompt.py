from typing import Any

from mcp.types import GetPromptResult, Prompt


class BasePrompt:
    name: str
    description: str

    def to_prompt(self) -> Prompt:
        return Prompt(
            name=self.name,
            description=self.description,
        )

    async def get(self, **kwargs: Any) -> GetPromptResult:
        raise NotImplementedError
