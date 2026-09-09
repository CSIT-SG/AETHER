from pathlib import Path
from typing import Annotated, cast

from aether_backend.forwarded_rpc import get_functions_called_recursively
from aether_backend.utils.effect import Program, Progress, effectful
from aether_backend.utils.get_rpc_service import get_rpc_service
from aether_backend.utils.validation import HexAddress
from aether_rpc.capabilities.types import FunctionTreeResult
from aether_utils.config import get_config
from aether_utils.get_content import get_content
from fastmcp.tools import tool
from mcp_types import ToolAnnotations

from .annotate_function import annotate
from .constants import TIMEOUT_SECONDS

INSTRUCTIONS = get_content(Path(__file__).parent, "instructions.md")


config = get_config()


@tool(
    description=INSTRUCTIONS,
    annotations=ToolAnnotations(title="Annotate Function", destructive_hint=True),
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
    ] = "",
) -> Program:

    svc = await get_rpc_service(rpc_id)

    if config.backup:
        svc.take_snapshot()

    res = await get_functions_called_recursively(svc, address=address)
    if not res.success:
        raise RuntimeError(f"Failed to get functions called recursively: {res.result}")

    funcs = cast(FunctionTreeResult, res.result)
    yield Progress(f"Found {funcs['count']} interesting child functions for {address}.")
    async for effect in annotate(svc, funcs, custom_prompt):
        yield effect
