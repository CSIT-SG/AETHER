from pathlib import Path
from typing import Annotated

from aether_backend.utils.effect import effectful
from aether_backend.utils.get_rpc_service import get_rpc_service
from aether_utils.config import get_config
from aether_utils.get_content import get_content
from fastmcp.tools import tool
from mcp.types import ToolAnnotations

from ..types import StructFieldOperation
from .constants import TIMEOUT_SECONDS

INSTRUCTIONS = get_content(Path(__file__).parent, "instructions.md")


config = get_config()


@tool(
    description=INSTRUCTIONS,
    annotations=ToolAnnotations(title="Annotate Function", destructiveHint=True),
    timeout=TIMEOUT_SECONDS,
)  # tool is untyped in fastmcp
@effectful  # type: ignore
async def mange_struct_field(
    rpc_id: Annotated[
        str, "The ID of the RPC service/IDB to use. Formatted as `<file_name>_<date>-<time>`."
    ],
    operation: Annotated[
        StructFieldOperation,
        "operation to be performed on a specified struct field.",
    ],
    struct_name: Annotated[str, "name of the struct which being referenced."],
    field_name: Annotated[
        str | None,
        "name of the field to modify or create.",
    ] = None,
    field_size: Annotated[int | None, "size of the field specified in field_name."] = None,
    field_type: Annotated[str | None, "type of data for the field specified in field_name."] = None,
    field_new_name: Annotated[str | None, "new field name for rename operations."] = None,
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
        case StructFieldOperation.UPDATE_NAME:
            ...
        case StructFieldOperation.UPDATE_SIZE:
            ...
        case StructFieldOperation.UPDATE_TYPE:
            ...
        case StructFieldOperation.DELETE:
            ...
        case _:
            raise ValueError(f"invalid field operation: {operation}")

    return True  # getting mypy to stop erroring for now
