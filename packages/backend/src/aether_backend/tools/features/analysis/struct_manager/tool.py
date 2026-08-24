from collections.abc import Awaitable, Callable, Iterable
from pathlib import Path
from typing import Annotated, Any

from aether_backend.forwarded_rpc import (
    add_struct_field,
    change_struct_field_size,
    change_struct_field_type,
    create_struct,
    delete_struct_field,
    get_data_at_address,
    get_function_pseudocode,
    get_struct_id_by_name,
    get_struct_info,
    rename_struct,
    rename_struct_field,
)
from aether_backend.utils.effect import Log, Program, effectful
from aether_backend.utils.get_rpc_service import get_rpc_service
from aether_backend.utils.subagent import SubagentToolDependencies
from aether_rpc.capabilities.types import XrefsResult
from aether_utils.config import get_config
from aether_utils.get_content import get_content
from agents import Runner
from fastmcp.tools import tool
from mcp.types import ToolAnnotations

from ..types import StructOperation
from .constants import TIMEOUT_SECONDS
from .utils import create_agent

INSTRUCTIONS = get_content(Path(__file__).parent, "instructions.md")


config = get_config()


@tool(
    description=INSTRUCTIONS,
    annotations=ToolAnnotations(title="manage struct", destructiveHint=True),
    timeout=TIMEOUT_SECONDS,
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def manage_struct(
    rpc_id: Annotated[
        str, "The ID of the RPC service/IDB to use. Formatted as `<file_name>_<date>-<time>`."
    ],
    xrefs: Annotated[list[XrefsResult], "list of Xrefs to the target variable"],
    operation: Annotated[StructOperation, "Operation to perform on the struct"],
    var_name: Annotated[str, "name of target variable for which to create the struct"],
    custom_prompt: Annotated[
        str | None,
        "A hint regarding behavior for the subagent to guide analysis. Keep it less than 3 sentences.",
    ] = None,
) -> Program:

    tool_list: Iterable[Callable[..., Awaitable[Any]]]

    svc = await get_rpc_service(rpc_id)

    if config.backup:
        svc.take_snapshot()

    if custom_prompt is None:
        custom_prompt = ""

    match operation:
        case StructOperation.CREATE:
            tool_list = [
                get_function_pseudocode,
                get_data_at_address,
                add_struct_field,
                create_struct,
                get_function_pseudocode,
            ]
        case StructOperation.UPDATE:
            tool_list = [
                get_function_pseudocode,
                get_data_at_address,
                change_struct_field_size,
                change_struct_field_type,
                delete_struct_field,
                get_struct_info,
                rename_struct,
                rename_struct_field,
                get_struct_id_by_name,
            ]
        case StructOperation.DELETE:
            ...
            yield Log("Deleted hehe")
            return

    agent = create_agent(tool_list)

    result = Runner.run_streamed(
        agent,
        context=SubagentToolDependencies(svc),
        input=(
            f"{operation} the struct representative of {var_name}"
            f"For added context you are to take a look at {xrefs}. These are the cross references to {var_name}"
            f"{custom_prompt}"
        ),
        max_turns=100000,
    )

    yield result.final_output
