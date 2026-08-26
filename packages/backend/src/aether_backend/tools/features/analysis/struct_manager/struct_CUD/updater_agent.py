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
from aether_backend.utils.validation import HexAddress
from aether_rpc.capabilities.types import XrefsResult

from ..types import StructOperation
from ..utils import create_agent, run_agent


async def build_and_run_updater(
    service: Any,
    *,
    operation: StructOperation,
    function_address: HexAddress,
    function_name: str,
    var_name: str,
    xrefs: XrefsResult,
    custom_prompt: str | None = None,
) -> Program:
    name = "struct updater"
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
    agent = create_agent(tool_list, system_prompt, name)
    result = run_agent(
        service,
        agent=agent,
        operation=operation,
        function_address=function_address,
        function_name=function_name,
        var_name=var_name,
        xrefs=xrefs,
        custom_prompt=custom_prompt,
    )
    yield Return(result)
