from typing import cast

from aether_backend.constants import ToolTags
from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.rpc_discovery import RPCRegistry
from fastmcp.dependencies import CurrentContext
from fastmcp.server.context import Context
from fastmcp.tools import tool

from .test_tool import test


@tool(tags={ToolTags.DEBUG})  # tool is untyped in fastmcp
@effectful  # type: ignore
async def test_tool(
    rpc_id: str, func_name: str, arguments: dict, ctx: Context = CurrentContext()
) -> Program:
    """Test a function with the given arguments."""
    registry = cast(RPCRegistry, ctx.lifespan_context["rpc_registry"])
    async for effect in test(await registry.get(rpc_id), func_name, **arguments):
        yield effect
