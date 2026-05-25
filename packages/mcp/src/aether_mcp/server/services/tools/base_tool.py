from typing import Any

from mcp.types import CallToolResult, Tool


class BaseTool:
    name: str
    description: str
    input_schema: dict[str, Any]

    def to_tool(self) -> Tool:
        return Tool(
            name=self.name,
            description=self.description,
            inputSchema=self.input_schema,
        )

    async def run(self, **kwargs: Any) -> CallToolResult:
        raise NotImplementedError
