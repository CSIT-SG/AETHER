from abc import ABC, abstractmethod
from typing import Any

from mcp.types import CallToolResult, Tool


class BaseTool(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def description(self) -> str: ...

    @property
    @abstractmethod
    def input_schema(self) -> dict[str, Any]: ...

    def to_tool(self) -> Tool:
        return Tool(
            name=self.name,
            description=self.description,
            inputSchema=self.input_schema,
        )

    @abstractmethod
    async def run(self, **kwargs: Any) -> CallToolResult:
        raise NotImplementedError
