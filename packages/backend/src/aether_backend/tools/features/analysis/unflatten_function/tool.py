from typing import Annotated

from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.get_rpc_service import get_rpc_service
from fastmcp.tools import tool
from mcp_types import ToolAnnotations

from .constants import TIMEOUT_SECONDS
from .unflatten_function import unflatten


@tool(
    task=True,
    annotations=ToolAnnotations(title="Unflatten Function"),
    timeout=TIMEOUT_SECONDS,
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def unflatten_function(
    rpc_id: Annotated[
        str, "The ID of the RPC service/IDB to use. Formatted as `<file_name>_<date>-<time>`."
    ],
    function_name: Annotated[str, "The name of the function to unflatten."],
    custom_prompt: Annotated[
        str | None,
        "A hint regarding behavior for the subagent to guide analysis. Keep it less than 3 sentences.",
    ] = "",
) -> Program:
    svc = await get_rpc_service(rpc_id)
    async for effect in unflatten(svc, function_name, custom_prompt):
        yield effect
