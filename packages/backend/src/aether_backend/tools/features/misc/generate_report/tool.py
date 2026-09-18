from typing import Annotated

from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.get_rpc_service import get_rpc_service
from fastmcp.tools import tool
from mcp_types import ToolAnnotations

from .constants import TIMEOUT_SECONDS
from .generate_report import generate_report_cb


@tool(
    task=True,
    annotations=ToolAnnotations(title="Generate Report", destructive_hint=True),
    timeout=TIMEOUT_SECONDS,
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def generate_report(
    rpc_id: Annotated[
        str, "The ID of the RPC service/IDB to use. Formatted as `<file_name>_<date>-<time>`."
    ],
    function_name: Annotated[str, "The name of the function to generate a report for."],
) -> Program:

    svc = await get_rpc_service(rpc_id)

    async for effect in generate_report_cb(svc, function_name):
        yield effect
