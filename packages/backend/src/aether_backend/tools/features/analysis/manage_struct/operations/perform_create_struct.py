from pathlib import Path
from typing import Any

from aether_backend.forwarded_rpc import (
    add_struct_field,
    apply_struct,
    create_struct,
    get_data_at_address,
    get_function_by_address,
    get_function_pseudocode,
    list_structs,
)
from aether_backend.utils.effect import Log, Program
from aether_backend.utils.validation import HexAddress
from aether_rpc.capabilities.variables.types import XrefsResult
from aether_utils.get_content import get_content

from ..utils import create_agent, run_agent


async def perform_create_struct(
    service: Any,
    *,
    function_address: HexAddress,
    var_name: str,
    xrefs: XrefsResult,
    custom_prompt: str | None = None,
) -> Program:
    func = await get_function_by_address(service=service, address=function_address)
    yield Log(f"{func}")
    if func.success is False:
        raise RuntimeError(f"Unable to get function {function_address}")

    struct_list = await list_structs(service=service)
    function_name = func.result["name"]
    user_prompt = f"These are the current structs in the idb file {struct_list} Create the struct representative of {var_name} which is found in the function {function_name} at {function_address} For added context you are to take a look at {xrefs}. These are the cross references to {var_name}. GIVE THE STRUCT AND IT'S FIELDS MEANINGFUL NAMES"
    name = "struct creator"
    system_prompt = get_content(Path(__file__).parent, "struct_creator_prompt.md")
    tool_list = [
        apply_struct,
        get_function_pseudocode,
        get_data_at_address,
        add_struct_field,
        create_struct,
    ]
    agent = create_agent(tool_list, system_prompt, name)
    async for effect in run_agent(
        service,
        agent=agent,
        user_prompt=user_prompt,
        custom_prompt=custom_prompt,
    ):
        yield effect
