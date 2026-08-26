from typing import Any

from aether_backend.forwarded_rpc import (
    add_struct_field,
    create_struct,
    get_data_at_address,
    get_function_by_address,
    get_function_pseudocode,
)
from aether_backend.utils.effect import Program, Return
from aether_backend.utils.validation import HexAddress
from aether_rpc.capabilities.types import XrefsResult

from ..utils import create_agent, run_agent


async def perform_create_struct(
    service: Any,
    *,
    function_address: HexAddress,
    function_name: str,
    var_name: str,
    xrefs: XrefsResult,
    custom_prompt: str | None = None,
) -> Program:
    func = await get_function_by_address(service, address=function_address)
    if func.success is False:
        raise RuntimeError(f"Unable to get function {function_address}")
    function_name = func.result["name"]
    user_prompt = f"create the struct representative of {var_name} which is found in the function {function_name} at {function_address} For added context you are to take a look at {xrefs}. These are the cross references to {var_name}"
    name = "struct creator"
    system_prompt = get_content(Path(__file__).parent, "struct_creator_prompt.md")
    tool_list = [
        get_function_pseudocode,
        get_data_at_address,
        add_struct_field,
        create_struct,
    ]
    agent = create_agent(tool_list, system_prompt, name)
    result = run_agent(
        service,
        agent=agent,
        user_prompt=user_prompt,
        custom_prompt=custom_prompt,
    )
    yield Return(result)
