from typing import cast

from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.rpc_discovery import RPC_REGISTRY_KEY, RPCRegistry
from fastmcp.dependencies import CurrentContext
from fastmcp.server.context import Context
from fastmcp.tools import tool
from mcp.types import ToolAnnotations

from .annotate_function import annotate
from .constants import TIMEOUT_SECONDS


@tool(
    annotations=ToolAnnotations(title="Annotator Subagent", destructiveHint=True),
    timeout=TIMEOUT_SECONDS,
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def annotate_function(
    rpc_id: str, address: str | int, ctx: Context = CurrentContext()
) -> Program:
    """Annotate a function at the given address."""
    registry = cast(RPCRegistry, ctx.lifespan_context[RPC_REGISTRY_KEY])
    async for effect in annotate(await registry.get(rpc_id), address):
        yield effect
