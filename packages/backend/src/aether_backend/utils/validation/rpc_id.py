from typing import Any

from aether_backend.utils.rpc_discovery import RPC_REGISTRY_KEY
from fastmcp.server.dependencies import get_context


async def validate_service(rpc_id: str) -> Any:
    """Validate the RPC ID and return the corresponding RPCRegistry."""
    ctx = get_context()
    registry = ctx.lifespan_context[RPC_REGISTRY_KEY]
    service = await registry.get(rpc_id)
    if service:
        return service
    raise ValueError(f"RPC registry has no connection with RPC server {rpc_id}")
