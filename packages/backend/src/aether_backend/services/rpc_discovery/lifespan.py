from collections.abc import AsyncIterator
from typing import Any

from fastmcp.server.lifespan import lifespan

from .constants import RPC_REGISTRY_KEY
from .registry import RPCRegistry


@lifespan
async def rpc_lifespan(_server: Any) -> AsyncIterator[dict[str, RPCRegistry]]:
    registry = RPCRegistry()
    try:
        await registry.start()
        yield {RPC_REGISTRY_KEY: registry}
    finally:
        await registry.stop()
