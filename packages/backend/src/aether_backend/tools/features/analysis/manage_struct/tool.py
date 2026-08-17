from pathlib import Path
from typing import Annotated

from aether_backend.utils.effect import effectful
from aether_backend.utils.get_rpc_service import get_rpc_service
from aether_utils.config import get_config
from aether_utils.get_content import get_content
from fastmcp.tools import tool
from mcp.types import ToolAnnotations

from ..types import StructField, StructOperation
from .constants import TIMEOUT_SECONDS

INSTRUCTIONS = get_content(Path(__file__).parent, "instructions.md")


config = get_config()


@tool(
    description=INSTRUCTIONS,
    annotations=ToolAnnotations(title="Annotate Function", destructiveHint=True),
    timeout=TIMEOUT_SECONDS,
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def mange_struct(
    rpc_id: Annotated[
        str, "The ID of the RPC service/IDB to use. Formatted as `<file_name>_<date>-<time>`."
    ],
    operation: Annotated[
        StructOperation,
        "Operation to be performed on a struct.",
    ],
    name: Annotated[str, "name of the struct to create."],
    new_name: Annotated[
        str | None,
        "name to rename the struct to. Only required for rename operation.",
    ] = None,
    fields: Annotated[
        list[StructField] | None, "list of struct fields to add to struct when creating."
    ] = None,
    custom_prompt: Annotated[
        str | None,
        "A hint regarding behavior for the subagent to guide analysis. Keep it less than 3 sentences.",
    ] = None,
) -> bool:

    svc = await get_rpc_service(rpc_id)

    if config.backup:
        svc.take_snapshot()

    if custom_prompt is None:
        custom_prompt = ""

    match operation:
        case StructOperation.CREATE:
            if fields is None:
                raise ValueError("Field is required for stuct creation.")
            ...
        case StructOperation.UPDATE_NAME:
            if new_name is None:
                raise ValueError("new_name is required for rename operation.")
            ...
        case StructOperation.GET:
            ...
        case StructOperation.DELETE:
            ...
        case StructOperation.ADD_FIELDS:
            if fields is None:
                raise ValueError("Field is required to add fields.")
            ...
        case _:
            raise ValueError(f"invalid operation: {operation}")

    return True  # getting mypy to stop erroring for now
