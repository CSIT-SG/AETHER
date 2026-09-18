from typing import cast

from aether_backend.services.rpc_discovery import RPC_REGISTRY_KEY
from fastmcp.server.dependencies import get_context

from .types import AnyService


async def get_rpc_service(rpc_id: str) -> AnyService:
    """Validate the RPC ID and return the corresponding RPCRegistry."""
    ctx = get_context()
    registry = ctx.lifespan_context[RPC_REGISTRY_KEY]
    service = await registry.get(rpc_id)
    if service:
        return cast(AnyService, service)
    raise ValueError(f"RPC registry has no connection with RPC server {rpc_id}")
