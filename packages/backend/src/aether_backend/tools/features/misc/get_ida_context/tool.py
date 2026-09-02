from pathlib import Path

from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.get_rpc_service import get_rpc_service
from aether_backend.utils.validation import HexAddress
from aether_utils.get_content import get_content
from fastmcp import Context
from fastmcp.tools import tool
from mcp.types import ToolAnnotations

from .get_ida_context import get_context

INSTRUCTIONS = get_content(Path(__file__).parent, "instructions.md")


@tool(
    description=INSTRUCTIONS,
    annotations=ToolAnnotations(
        title="Fetch reverse-engineering context at address", openWorldHint=True
    ),
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def get_function_context(rpc_id: str, address: HexAddress, ctx: Context) -> Program:
    async for effect in get_context(await get_rpc_service(rpc_id, ctx), address):
        yield effect
