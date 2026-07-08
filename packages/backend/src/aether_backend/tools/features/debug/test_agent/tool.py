from typing import Any

from aether_backend.constants import ToolTags
from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.validation import get_service
from fastmcp.tools import tool

from .tester_agent import test


@tool(tags={ToolTags.DEBUG})  # tool is untyped in fastmcp
@effectful  # type: ignore
async def test_agent(rpc_id: str, rpc_tool: str, arguments: dict[str, Any]) -> Program:
    """Test agent spawning by calling an rpc function with the given arguments."""
    async for effect in test(await get_service(rpc_id), rpc_tool, **arguments):
        yield effect
