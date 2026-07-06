from typing import Any, cast

from aether_backend.constants import ToolTags
from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.rpc_discovery import RPC_REGISTRY_KEY, RPCRegistry
from aether_backend.utils.validation import validate_rpc_id
from fastmcp.dependencies import CurrentContext
from fastmcp.server.context import Context
from fastmcp.tools import tool

from .tester_agent import test


@tool(tags={ToolTags.DEBUG})  # tool is untyped in fastmcp
@effectful  # type: ignore
async def test_agent(
    rpc_id: str, rpc_tool: str, arguments: dict[str, Any], ctx: Context = CurrentContext()
) -> Program:
    """Test agent spawning by calling an rpc function with the given arguments."""
    await validate_rpc_id(rpc_id)
    registry = cast(RPCRegistry, ctx.lifespan_context[RPC_REGISTRY_KEY])
    async for effect in test(await registry.get(rpc_id), rpc_tool, **arguments):
        yield effect
