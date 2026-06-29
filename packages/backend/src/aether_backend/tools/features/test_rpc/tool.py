from typing import Any, cast

from aether_backend.constants import ToolTags
from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.rpc_discovery import RPC_REGISTRY_KEY, RPCRegistry
from fastmcp.dependencies import CurrentContext
from fastmcp.server.context import Context
from fastmcp.tools import tool

from .tester_tool import test


@tool(tags={ToolTags.DEBUG})  # tool is untyped in fastmcp
@effectful  # type: ignore
async def test_tool(
    rpc_id: str, func_name: str, arguments: dict[str, Any], ctx: Context = CurrentContext()
) -> Program:
    """Test a function with the given arguments."""
    registry = cast(RPCRegistry, ctx.lifespan_context[RPC_REGISTRY_KEY])
    async for effect in test(await registry.get(rpc_id), func_name, **arguments):
        yield effect
