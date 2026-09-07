from typing import Annotated

from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.get_rpc_service import get_rpc_service
from aether_backend.utils.validation import HexAddress
from aether_utils.config import get_config
from fastmcp.tools import tool
from mcp_types import ToolAnnotations

from .constants import TIMEOUT_SECONDS
from .generate_report import generate_report

config = get_config()


@tool(
    annotations=ToolAnnotations(title="Generate Report", destructive_hint=True),
    timeout=TIMEOUT_SECONDS,
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def generate_report_tool(
    rpc_id: Annotated[
        str, "The ID of the RPC service/IDB to use. Formatted as `<file_name>_<date>-<time>`."
    ],
    address: Annotated[
        HexAddress, "The hexadecimal effective address of the function to generate a report for."
    ],
) -> Program:

    svc = await get_rpc_service(rpc_id)

    async for effect in generate_report(svc, address):
        yield effect
