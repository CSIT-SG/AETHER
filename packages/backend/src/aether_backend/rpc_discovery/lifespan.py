from collections.abc import AsyncIterator
from typing import Any

from fastmcp.server.lifespan import lifespan

from .registry import RpcRegistry


@lifespan
async def rpc_lifespan(_server: Any) -> AsyncIterator[dict[str, RpcRegistry]]:
    registry = RpcRegistry()
    try:
        await registry.start()
        yield {"rpc_registry": registry}
    finally:
        await registry.stop()
