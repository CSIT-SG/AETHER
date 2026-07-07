from pathlib import Path

from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.get_content import get_content
from aether_backend.utils.validation import HexAddress, validate_service
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
) -> Program:
    """Annotate a function at the given address."""
    async for effect in annotate(await validate_service(rpc_id), address, custom_prompt):
        yield effect
