from collections.abc import Callable
from contextlib import _AsyncGeneratorContextManager

import pytest
from fastmcp import Client


@pytest.mark.asyncio
@pytest.mark.dependency(name="connection", scope="session")
async def test_fastmcp_lists_tools(mcp_client: Callable[[], _AsyncGeneratorContextManager[Client]]):
    """Verifies that the MCP server can return tools from the RPC server."""
    # Await the high-level fastmcp method directly
    async with mcp_client() as client:
        response = await client.call_tool(
            "list_rpc_connections",
        )
        content = response.content
        assert len(content) > 0
        if content[0].type == "text" and list(content[0].text) != 0:
            assert len(list(content[0].text)) != 0
