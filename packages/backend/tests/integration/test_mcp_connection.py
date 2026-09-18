import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport


@pytest.mark.asyncio
@pytest.mark.dependency(name="connection", scope="package")
async def test_mcp_connection(
    mcp_client: Client[StreamableHttpTransport],
) -> None:
    """Verifies that the MCP server can return tools from the RPC server."""
    # Await the high-level fastmcp method directly
    response = await mcp_client.call_tool(
        "list_rpc_connections",
    )
    content = response.content
    assert len(content) > 0
    if content[0].type == "text" and list(content[0].text) != 0:
        assert len(list(content[0].text)) != 0
