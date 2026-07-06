from pathlib import Path
from typing import cast

from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.get_content import get_content
from aether_backend.utils.rpc_discovery import RPC_REGISTRY_KEY, RPCRegistry
from aether_backend.utils.validation import HexAddress, validate_service
from fastmcp.dependencies import CurrentContext
from fastmcp.server.context import Context
from fastmcp.tools import tool
from mcp.types import ToolAnnotations

from .annotate_function import annotate
from .constants import TIMEOUT_SECONDS

INSTRUCTIONS = get_content(Path(__file__).parent, "instructions.md")


@tool(
    description=INSTRUCTIONS,
    annotations=ToolAnnotations(title="Annotate Function", destructiveHint=True),
    timeout=TIMEOUT_SECONDS,
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def annotate_function(
    rpc_id: str,
    address: HexAddress,
    custom_prompt: str | None = None,
    ctx: Context = CurrentContext(),
) -> Program:
    """Annotate a function at the given address."""
    registry = cast(RPCRegistry, ctx.lifespan_context[RPC_REGISTRY_KEY])
    async for effect in annotate(await validate_service(registry, rpc_id), address, custom_prompt):
        yield effect
