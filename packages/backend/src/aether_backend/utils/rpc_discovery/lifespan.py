from collections.abc import AsyncIterator
from typing import Any

from fastmcp.server.lifespan import lifespan

from .registry import RPCRegistry


@lifespan
async def rpc_lifespan(_server: Any) -> AsyncIterator[dict[str, RPCRegistry]]:
    registry = RPCRegistry()
    try:
        await registry.start()
        yield {"rpc_registry": registry}
    finally:
        await registry.stop()
