from pathlib import Path
from typing import Any

from aether_backend.forwarded_rpc import (
    change_struct_field_size,
    change_struct_field_type,
    delete_struct_field,
    get_data_at_address,
    get_function_by_address,
    get_function_pseudocode,
    get_struct_id_by_name,
    get_struct_info,
    rename_struct,
    rename_struct_field,
)
from aether_backend.utils.effect import Program, Return
from aether_backend.utils.validation import HexAddress
from aether_rpc.capabilities.types import XrefsResult
from aether_utils.get_content import get_content

from ..utils import create_agent, run_agent


async def perform_update_struct(
    service: Any,
    *,
    function_address: HexAddress,
    var_name: str,
    xrefs: XrefsResult,
    custom_prompt: str | None = None,
) -> Program:
    func = await get_function_by_address(service=service, address=function_address)
    if func.success is False:
        raise RuntimeError(f"Unable to get function {function_address}")
    function_name = func.result["name"]
    user_prompt = f"update the struct representative of {var_name} which is found in the function {function_name} at {function_address} For added context you are to take a look at {xrefs}. These are the cross references to {var_name}"
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
        user_prompt=user_prompt,
        custom_prompt=custom_prompt,
    )
    yield Return(result)
