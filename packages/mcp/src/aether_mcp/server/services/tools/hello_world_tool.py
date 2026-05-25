from typing import Any

from mcp.types import CallToolResult, TextContent

from .base_tool import BaseTool


class HelloWorld(BaseTool):
    name = "hello_world"
    description = "Returns hello world"
    input_schema = {
        "type": "object",
        "properties": {
            "word": {"type": "string", "description": "Changes output depending on input"},
        },
        "required": ["word"],
    }

    async def run(self, **kwargs: Any) -> CallToolResult:
        word: str = kwargs["word"]
        output = "world" if word == "hello" else "huh"
        return CallToolResult(content=[TextContent(type="text", text=f"{output}")])
