from typing import Annotated

from aether_backend.utils.effect import Log, Program, effectful
from aether_backend.utils.get_rpc_service import get_rpc_service
from aether_utils.config import get_config
from fastmcp.tools import tool
from mcp.types import ToolAnnotations

from .collect_pseudocode import collect_pseudocode
from .constants import TIMEOUT_SECONDS

config = get_config()


@tool(
    annotations=ToolAnnotations(title="Index Functions", destructiveHint=True),
    timeout=TIMEOUT_SECONDS,
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def index_functions(
    rpc_id: Annotated[
        str, "The ID of the RPC service/IDB to use. Formatted as `<file_name>_<date>-<time>`."
    ],
) -> Program:

    svc = await get_rpc_service(rpc_id)
    async for pseudocode_yield in collect_pseudocode(svc):
        # await asyncio.sleep(0.01)
        if pseudocode_yield.success:
            yield Log(f"Successfully retrieved pseudocode:\n{pseudocode_yield.result}")
        else:
            yield Log(f"Failed to retrieve pseudocode: {pseudocode_yield.result}")
