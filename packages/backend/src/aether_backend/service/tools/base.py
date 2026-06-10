from abc import ABC, abstractmethod
from typing import Any
from pydantic import BaseModel
from mcp.server.fastmcp import Context
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
    def input_schema(self) -> BaseModel: ...

    @abstractmethod
    async def handler(self, ctx: Context[Any, Any], **kwargs: Any) -> CallToolResult: ...

    def to_tool(self) -> Tool:
        return Tool(
            name=self.name,
            description=self.description,
            inputSchema=self.input_schema.model_json_schema(),
        )
