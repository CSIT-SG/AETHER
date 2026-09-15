import json

from fastmcp.client.client import CallToolResult
from mcp_types import TextContent


def deserialise_call_tool_result(result: CallToolResult) -> str:
    """Flatten a tool result into the text handed to both the LLM and the UI."""
    texts = [block.text for block in result.content if isinstance(block, TextContent)]
    if texts:
        return "\n".join(texts)
    if result.structured_content is not None:
        try:
            return json.dumps(result.structured_content)
        except (TypeError, ValueError):
            pass
    return str(result)
