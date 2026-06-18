from aether_backend.utils.effect import Program, effectful, Log
from fastmcp.tools import tool
from fastmcp.server.context import Context
from fastmcp.dependencies import CurrentContext

from .annotate_function import annotate
from aether_backend.utils.rpc_discovery import RPCRegistry
from typing import cast

@tool  # tool is untyped in fastmcp
@effectful  # type: ignore
async def annotate_function(rpc_id: str, address: str | int, ctx: Context = CurrentContext()) -> Program:
    """Annotate a function at the given address."""
    registry = cast(RPCRegistry, ctx.lifespan_context["rpc_registry"])
    async for effect in annotate(await registry.get(rpc_id), address):
        yield effect
