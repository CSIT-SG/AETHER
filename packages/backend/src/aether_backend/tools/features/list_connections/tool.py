from typing import cast

from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.rpc_discovery import RPCRegistry
from fastmcp.dependencies import CurrentContext
from fastmcp.server.context import Context
from fastmcp.tools import tool

from .list_connections import list_connections_cb


@tool  # tool is untyped in fastmcp
@effectful  # type: ignore
async def list_connections(ctx: Context = CurrentContext()) -> Program:
    """Annotate a function at the given address."""
    registry = cast(RPCRegistry, ctx.lifespan_context["rpc_registry"])
    async for effect in list_connections_cb(await registry.ids()):
        yield effect
