from typing import cast

from aether_backend.services.rpc_discovery import RPC_REGISTRY_KEY
from fastmcp import Context

from .types import AnyService


async def get_rpc_service(rpc_id: str, ctx: Context) -> AnyService:
    """Validate the RPC ID and return the corresponding RPCRegistry.

    Args:
        rpc_id: The RPC server ID to retrieve.
        ctx: FastMCP context (injected automatically).
    """
    registry = ctx.lifespan_context[RPC_REGISTRY_KEY]
    service = await registry.get(rpc_id)
    if service:
        return cast(AnyService, service)
    raise ValueError(f"RPC registry has no connection with RPC server {rpc_id}")
