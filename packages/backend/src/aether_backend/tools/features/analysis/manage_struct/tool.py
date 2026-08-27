from pathlib import Path
from typing import Annotated

from aether_backend.utils.effect import Log, Program, effectful
from aether_backend.utils.get_rpc_service import get_rpc_service
from aether_backend.utils.validation import HexAddress
from aether_utils.config import get_config
from aether_utils.get_content import get_content
from fastmcp.tools import tool
from mcp.types import ToolAnnotations

from .constants import TIMEOUT_SECONDS
from .operations import perform_create_struct, perform_delete_struct, perform_update_struct
from .types import StructOperation
from .utils import resolve_xrefs

INSTRUCTIONS = get_content(Path(__file__).parent, "instructions.md")


config = get_config()


@tool(
    description=INSTRUCTIONS,
    annotations=ToolAnnotations(title="Manage Struct", destructiveHint=True),
    timeout=TIMEOUT_SECONDS,
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def manage_struct(
    rpc_id: Annotated[
        str, "The ID of the RPC service/IDB to use. Formatted as `<file_name>_<date>-<time>`."
    ],
    operation: Annotated[StructOperation, "Operation to perform on the struct"],
    function_address: Annotated[
        HexAddress, "The hexadecimal effective address of the function to annotate."
    ],
    var_name: Annotated[str, "name of target variable for which to create the struct"],
    custom_prompt: Annotated[
        str | None,
        "A hint regarding behavior for the subagent to guide analysis. Keep it less than 3 sentences.",
    ] = None,
) -> Program:

    svc = await get_rpc_service(rpc_id)

    if config.backup:
        svc.take_snapshot()

    if custom_prompt is None:
        custom_prompt = ""

    match operation:
        case StructOperation.CREATE:
            refs = await resolve_xrefs(svc, var_name)
            async for effect in perform_create_struct(
                svc,
                function_address=function_address,
                var_name=var_name,
                xrefs=refs,
                custom_prompt=custom_prompt,
            ):
                yield effect
        case StructOperation.UPDATE:
            refs = await resolve_xrefs(svc, var_name)
            async for effect in perform_update_struct(
                svc,
                function_address=function_address,
                var_name=var_name,
                xrefs=refs,
                custom_prompt=custom_prompt,
            ):
                yield effect
        case StructOperation.DELETE:
            deleted = await perform_delete_struct(
                svc, function_address=function_address, var_name=var_name
            )
            yield Log(f"Deleted struct {deleted}")
            return
