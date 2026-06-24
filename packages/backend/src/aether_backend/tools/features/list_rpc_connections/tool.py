from typing import cast

from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.rpc_discovery import RPCRegistry
from fastmcp.dependencies import CurrentContext
from fastmcp.server.context import Context
from fastmcp.tools import tool

from .list_rpc_connections import list_rpc_connections as list_rpc_connections_cb


@tool  # tool is untyped in fastmcp
@effectful  # type: ignore
async def list_rpc_connections(ctx: Context = CurrentContext()) -> Program:
    """List all active connection ids to the IDA remote procedure call servers.
    Each id is formatted `<file_name>_<date>-<time>`.
    """
    registry = cast(RPCRegistry, ctx.lifespan_context["rpc_registry"])
    async for effect in list_rpc_connections_cb(await registry.ids()):
        yield effect
