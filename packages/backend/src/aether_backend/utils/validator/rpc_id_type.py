from typing import Annotated, cast

from aether_backend.utils.rpc_discovery import RPC_REGISTRY_KEY, RPCRegistry
from fastmcp.server.context import Context
from fastmcp.server.dependencies import get_context
from pydantic import BeforeValidator, Field


async def _validate_rpc_id(rpc_id: str, ctx: Context = get_context()) -> str:
    """Validate the RPC ID and return the corresponding RPCRegistry."""
    registry = cast(RPCRegistry, ctx.lifespan_context[RPC_REGISTRY_KEY])
    if not await registry.has(rpc_id):
        raise ValueError(f"RPC ID {rpc_id} is not registered.")
    return rpc_id


type RPCId = Annotated[
    str,
    BeforeValidator(_validate_rpc_id),
    Field(
        description="RPC id in the format <filename>-<time>",
        examples=["hello_20260706-120067", "world_20260706-001267"],
    ),
]
