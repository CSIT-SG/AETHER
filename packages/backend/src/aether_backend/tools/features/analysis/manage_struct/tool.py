from pathlib import Path
from typing import Annotated

from aether_backend.forwarded_rpc import get_stack_variable_xrefs
from aether_backend.utils.effect import Program, effectful
from aether_backend.utils.get_rpc_service import get_rpc_service
from aether_backend.utils.validation import HexAddress
from aether_utils.config import get_config
from aether_utils.get_content import get_content
from fastmcp.tools import tool
from mcp_types import ToolAnnotations

from .constants import TIMEOUT_SECONDS
from .operations import perform_create_struct, perform_update_struct
from .types import StructOperation

INSTRUCTIONS = get_content(Path(__file__).parent, "instructions.md")


@tool(
    task=True,
    description=INSTRUCTIONS,
    annotations=ToolAnnotations(title="Manage Struct", destructive_hint=True),
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

    if get_config().backup:
        svc.take_snapshot()

    if custom_prompt is None:
        custom_prompt = ""

    xrefs = await get_stack_variable_xrefs(
        svc, function_location=function_address, local_variable_name=var_name
    )
    if xrefs.success is False:
        raise RuntimeError(f"Unable to collect xrefs for {var_name}: {xrefs.result}")

    refs = xrefs.result

    match operation:
        case StructOperation.CREATE:
            async for effect in perform_create_struct(
                svc,
                function_address=function_address,
                var_name=var_name,
                xrefs=refs,
                custom_prompt=custom_prompt,
            ):
                yield effect
        case StructOperation.UPDATE:
            async for effect in perform_update_struct(
                svc,
                function_address=function_address,
                var_name=var_name,
                xrefs=refs,
                custom_prompt=custom_prompt,
            ):
                yield effect
