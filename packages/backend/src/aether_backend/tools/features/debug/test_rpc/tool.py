from typing import Any

from aether_backend.constants import ToolTags
from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.validation import get_service
from fastmcp.tools import tool

from .tester_tool import test


@tool(tags={ToolTags.DEBUG})  # tool is untyped in fastmcp
@effectful  # type: ignore
async def test_tool(rpc_id: str, func_name: str, arguments: dict[str, Any]) -> Program:
    """Test a function with the given arguments."""
    async for effect in test(await get_service(rpc_id), func_name, **arguments):
        yield effect
