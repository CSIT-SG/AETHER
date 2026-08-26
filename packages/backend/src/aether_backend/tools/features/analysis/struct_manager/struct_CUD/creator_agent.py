from typing import Any

from aether_backend.forwarded_rpc import (
    add_struct_field,
    create_struct,
    get_data_at_address,
    get_function_pseudocode,
)
from aether_backend.utils.effect import Program, Return
from aether_rpc.capabilities.types import XrefsResult

from ..types import StructOperation
from ..utils import create_agent, run_agent


async def build_and_run_creator(
    service: Any,
    operation: StructOperation,
    var_name: str,
    xrefs: XrefsResult,
    custom_prompt: str | None = None,
) -> Program:
    system_prompt = get_content(Path(__file__).parent, "struct_creator_prompt.md")
    tool_list = [
        get_function_pseudocode,
        get_data_at_address,
        add_struct_field,
        create_struct,
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
