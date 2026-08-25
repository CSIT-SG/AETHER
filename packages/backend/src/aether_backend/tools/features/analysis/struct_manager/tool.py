from pathlib import Path
from typing import Annotated

from aether_backend.forwarded_rpc import get_xrefs_to
from aether_backend.utils.effect import Log, Program, effectful
from aether_backend.utils.get_rpc_service import get_rpc_service
from aether_utils.config import get_config
from aether_utils.get_content import get_content
from fastmcp.tools import tool
from mcp.types import ToolAnnotations

from .constants import TIMEOUT_SECONDS
from .struct_CUD import build_and_run_creator, build_and_run_updater
from .types import StructOperation

INSTRUCTIONS = get_content(Path(__file__).parent, "instructions.md")


config = get_config()


@tool(
    description=INSTRUCTIONS,
    annotations=ToolAnnotations(title="manage struct", destructiveHint=True),
    timeout=TIMEOUT_SECONDS,
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def struct_manager(
    rpc_id: Annotated[
        str, "The ID of the RPC service/IDB to use. Formatted as `<file_name>_<date>-<time>`."
    ],
    operation: Annotated[StructOperation, "Operation to perform on the struct"],
    var_name: Annotated[str, "name of target variable for which to create the struct"],
    custom_prompt: Annotated[
        str | None,
        "A hint regarding behavior for the subagent to guide analysis. Keep it less than 3 sentences.",
    ] = None,
) -> Program:

    svc = await get_rpc_service(rpc_id)

    xrefs = await get_xrefs_to(
        svc,
        location=var_name,
    )

    if xrefs.success is False:
        raise RuntimeError(f"Failed to get xrefs {xrefs.result}")

    refs = xrefs.result

    if config.backup:
        svc.take_snapshot()

    if custom_prompt is None:
        custom_prompt = ""

    match operation:
        case StructOperation.CREATE:
            build_and_run_creator(svc, operation, var_name, refs, custom_prompt)
        case StructOperation.UPDATE:
            build_and_run_updater(svc, operation, var_name, refs, custom_prompt)
        case StructOperation.DELETE:
            ...
            yield Log(f"Deleted struct at {var_name}")
            return
