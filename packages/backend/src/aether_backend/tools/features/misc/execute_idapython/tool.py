from pathlib import Path

from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.get_content import get_content
from aether_backend.utils.validation import get_service
from fastmcp.tools import tool
from mcp.types import ToolAnnotations

from .constants import TIMEOUT_SECONDS
from .execute_idapython import exec_code

INSTRUCTIONS = get_content(Path(__file__).parent, "instructions.md")


@tool(
    description=INSTRUCTIONS,
    annotations=ToolAnnotations(title="Execute IDAPython", openWorldHint=True),
    timeout=TIMEOUT_SECONDS,
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def execute_idapython(rpc_id: str, code: str) -> Program:
    async for effect in exec_code(await get_service(rpc_id), code):
        yield effect
