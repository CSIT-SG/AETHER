from pathlib import Path
from typing import Any

from aether_backend.forwarded_rpc import (
    add_struct_field,
    apply_struct,
    create_struct,
    get_function_by_address,
    get_function_pseudocode,
    list_structs,
)
from aether_backend.utils.effect import Program, Progress
from aether_backend.utils.validation import HexAddress
from aether_rpc.capabilities.types import XrefsResult
from aether_utils.config import get_config
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
    yield Progress(f"{func}")
    if func.success is False:
        raise RuntimeError(f"Unable to get function {function_address}")

    function_name = func.result["name"]
    user_prompt = f"Create the struct for {var_name} in function {function_name}. For added context you are to take a look at {xrefs}. GIVE THE STRUCT AND IT'S FIELDS MEANINGFUL NAMES."
    config = get_config()
    agent = create_agent(
        tool_list=[
            apply_struct,
            get_function_pseudocode,
            add_struct_field,
            create_struct,
            list_structs,
        ],
        system_prompt=get_content(Path(__file__).parent, "struct_creator_prompt.md"),
        name="struct creator",
        model_name=config.subagents.struct_creator_model if config.subagents else None,
        )
    async for effect in run_agent(
        service,
        agent=agent,
        user_prompt=user_prompt,
        custom_prompt=custom_prompt,
    ):
        yield effect
