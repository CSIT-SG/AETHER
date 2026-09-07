"""
from typing import Annotated

from aether_backend.utils.effect import Log, Program, effectful
from aether_backend.utils.get_rpc_service import get_rpc_service
from aether_utils.config import get_config
from fastmcp import Context
from fastmcp.tools import tool
from mcp_types import ToolAnnotations

from .constants import TIMEOUT_SECONDS

config = get_config()


@tool(
    annotations=ToolAnnotations(title="Index Functions", destructive_hint=True),
    timeout=TIMEOUT_SECONDS,
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def index_functions(
    rpc_id: Annotated[
        str, "The ID of the RPC service/IDB to use. Formatted as `<file_name>_<date>-<time>`."
    ],
) -> Program:

    svc = await get_rpc_service(rpc_id, ctx)
    yield Log(f"Using RPC service {rpc_id} at {svc.port} for indexing functions.")
"""
