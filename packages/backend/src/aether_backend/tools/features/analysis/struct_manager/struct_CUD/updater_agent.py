from typing import Any

from aether_backend.forwarded_rpc import (
    change_struct_field_size,
    change_struct_field_type,
    delete_struct_field,
    get_data_at_address,
    get_function_pseudocode,
    get_struct_id_by_name,
    get_struct_info,
    rename_struct,
    rename_struct_field,
)
from aether_backend.utils.effect import Program, Return
from aether_rpc.capabilities.types import XrefsResult

from ..types import StructOperation
from ..utils import create_agent, run_agent


async def build_and_run_updater(
    service: Any,
    *,
    operation: StructOperation,
    var_name: str,
    xrefs: XrefsResult,
    custom_prompt: str | None = None,
) -> Program:
    system_prompt = get_content(Path(__file__).parent, "struct_updater_prompt.md")
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
    agent = create_agent(tool_list, system_prompt)
    result = run_agent(
        service,
        agent=agent,
        operation=operation,
        var_name=var_name,
        xrefs=xrefs,
        custom_prompt=custom_prompt,
    )
    yield Return(result)
