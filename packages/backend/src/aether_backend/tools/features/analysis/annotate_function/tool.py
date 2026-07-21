from pathlib import Path
from typing import Annotated

from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.get_rpc_service import get_rpc_service
from aether_backend.utils.validation import HexAddress
from aether_utils.get_content import get_content
from fastmcp.tools import tool
from mcp.types import ToolAnnotations

from .annotate_function import annotate
from .constants import TIMEOUT_SECONDS
from .get_interesting_child_functions import get_interesting_child_functions

INSTRUCTIONS = get_content(Path(__file__).parent, "instructions.md")


@tool(
    description=INSTRUCTIONS,
    annotations=ToolAnnotations(title="Annotate Function", destructiveHint=True),
    timeout=TIMEOUT_SECONDS,
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def annotate_function(
    rpc_id: Annotated[
        str, "The ID of the RPC service/IDB to use. Formatted as `<file_name>_<date>-<time>`."
    ],
    address: Annotated[
        HexAddress, "The hexadecimal effective address of the function to annotate."
    ],
    custom_prompt: Annotated[
        str | None,
        "A hint regarding behavior for the subagent to guide analysis. Keep it less than 3 sentences.",
    ] = None,
) -> Program:

    svc = await get_rpc_service(rpc_id)
    funcs = await get_interesting_child_functions(svc, address, custom_prompt)

    async for effect in annotate(svc, address, funcs, custom_prompt):
        yield effect
