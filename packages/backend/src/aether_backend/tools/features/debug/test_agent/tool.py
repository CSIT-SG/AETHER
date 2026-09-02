from typing import Any

from aether_backend.constants import ToolChannels
from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.get_rpc_service import get_rpc_service
from fastmcp import Context
from fastmcp.tools import tool

from .tester_agent import test


@tool(tags={ToolChannels.DEBUG})  # tool is untyped in fastmcp
@effectful  # type: ignore
async def test_agent(
    rpc_id: str, rpc_tool: str, arguments: dict[str, Any], ctx: Context
) -> Program:
    """Test agent spawning by calling an rpc function with the given arguments."""
    async for effect in test(await get_rpc_service(rpc_id, ctx), rpc_tool, **arguments):
        yield effect
