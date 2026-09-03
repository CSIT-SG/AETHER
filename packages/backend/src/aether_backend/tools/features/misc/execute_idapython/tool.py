from pathlib import Path
from typing import Annotated

from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.get_rpc_service import get_rpc_service
from aether_utils.get_content import get_content
from fastmcp.tools import tool
from mcp.types import ToolAnnotations

from .constants import TIMEOUT_SECONDS
from .execute_idapython import exec_code

INSTRUCTIONS = get_content(Path(__file__).parent, "instructions.md")


@tool(
    description=INSTRUCTIONS,
    annotations=ToolAnnotations(title="Execute IDAPython", open_world_hint=True),
    timeout=TIMEOUT_SECONDS,
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def execute_idapython(
    rpc_id: Annotated[
        str, "The ID of the RPC service/IDB to use. Formatted as `<file_name>_<date>-<time>`."
    ],
    code: Annotated[str, "The IDAPython code to execute."],
) -> Program:
    async for effect in exec_code(await get_rpc_service(rpc_id), code):
        yield effect
