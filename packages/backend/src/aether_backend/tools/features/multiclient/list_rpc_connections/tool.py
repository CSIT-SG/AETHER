from typing import cast

from aether_backend.services.rpc_discovery import RPC_REGISTRY_KEY, RPCRegistry
from aether_backend.utils.effect import Program, effectful
from fastmcp.server.context import Context
from fastmcp.tools import tool
from mcp.types import ToolAnnotations

from .constants import TIMEOUT_SECONDS
from .list_rpc_connections import list_rpc_connections as list_rpc_connections_cb


@tool(
    annotations=ToolAnnotations(
        title="List RPC Connections",
        read_only_hint=True,
        idempotent_hint=True,
        destructive_hint=False,
    ),
    timeout=TIMEOUT_SECONDS,
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def list_rpc_connections(ctx: Context) -> Program:
    """List all active connection ids to the IDA remote procedure call servers.
    Each id is formatted `<file_name>_<date>-<time>`.
    """
    registry = cast(RPCRegistry, ctx.lifespan_context[RPC_REGISTRY_KEY])
    async for effect in list_rpc_connections_cb(await registry.ids()):
        yield effect
