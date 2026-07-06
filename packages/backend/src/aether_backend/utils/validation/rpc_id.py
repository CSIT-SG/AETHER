from typing import cast

from aether_backend.utils.rpc_discovery import RPC_REGISTRY_KEY, RPCRegistry
from fastmcp.server.dependencies import get_context


async def validate_rpc_id(rpc_id: str) -> str:
    """Validate the RPC ID and return the corresponding RPCRegistry."""
    ctx = get_context()
    registry = cast(RPCRegistry, ctx.lifespan_context[RPC_REGISTRY_KEY])
    if not await registry.has(rpc_id):
        raise ValueError(f"RPC ID {rpc_id} is not registered.")
    return rpc_id
