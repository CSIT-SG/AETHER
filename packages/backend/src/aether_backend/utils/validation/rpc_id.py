from typing import Any

from aether_backend.utils.rpc_discovery import RPCRegistry


async def validate_service(registry: RPCRegistry, rpc_id: str) -> Any:
    """Validate the RPC ID and return the corresponding RPCRegistry."""
    service = registry.get(rpc_id)
    if service:
        return service
    raise ValueError(f"RPC registry has no connection with RPC server {rpc_id}")
