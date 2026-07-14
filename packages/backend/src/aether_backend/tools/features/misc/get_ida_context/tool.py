from pathlib import Path

from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.get_content import get_content
from aether_backend.utils.validation import HexAddress, get_service
from fastmcp.tools import tool
from mcp.types import ToolAnnotations

from .get_ida_context import exec_code

INSTRUCTIONS = get_content(Path(__file__).parent, "instructions.md")


@tool(
    description=INSTRUCTIONS,
    annotations=ToolAnnotations(title="Get current IDA context", openWorldHint=True),
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def get_ida_context(rpc_id: str, address: HexAddress) -> Program:
    async for effect in exec_code(await get_service(rpc_id), address):
        yield effect
