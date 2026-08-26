from collections.abc import Awaitable, Callable, Iterable
from typing import Any, cast

from aether_backend.forwarded_rpc import get_function_by_address, get_local_variables
from aether_backend.utils.effect import Program
from aether_backend.utils.subagent import (
    SubagentToolDependencies,
    build_subagent_tool,
)
from aether_backend.utils.validation import HexAddress
from aether_rpc.capabilities.types import XrefsResult
from aether_utils.api_client import (
    OpenAIGateway,
)
from aether_utils.config import get_config
from agents import Agent, ModelSettings, Runner

from .types import StructOperation


def create_agent(
    tool_list: Iterable[Callable[..., Awaitable[Any]]], system_prompt: str, name: str
) -> Agent:
    config = get_config()
    agent = Agent(
        name=name,
        model=OpenAIGateway().get_model(
            model_name=config.subagents.annotator_model if config.subagents else None,
            feature=name,
        ),
        instructions=system_prompt,
        tools=list(
            map(
                build_subagent_tool,
                tool_list,
            )
        ),
        model_settings=ModelSettings(parallel_tool_calls=False),
    )
    return agent


async def run_agent(
    svc: Any,
    *,
    agent: Agent,
    operation: StructOperation,
    function_address: HexAddress,
    function_name: str,
    var_name: str,
    xrefs: XrefsResult,
    custom_prompt: str | None = None,
) -> Program:
    result = Runner.run_streamed(
        agent,
        context=SubagentToolDependencies(svc),
        input=(
            f"{operation} the struct representative of {var_name} which is found in the function {function_name} at {function_address}"
            f"For added context you are to take a look at {xrefs}. These are the cross references to {var_name}"
            f"{custom_prompt}"
        ),
        max_turns=100000,
    )

    return result.final_output


async def get_var_type(svc: Any, function_address: HexAddress, variable: str) -> str:
    func = await get_function_by_address(svc, address=function_address)
    if func.success is False:
        raise RuntimeError(f"Unable to get function {function_address}")
    func_name = func.result["name"]
    lvars = await get_local_variables(svc, function_name=func_name)
    if lvars.success is False:
        raise RuntimeError("Unable to get local vairables")
    for var in lvars.result:
        if var["name"] == variable:
            return cast(str, var["type"])
    raise RuntimeError(f"variable {variable} not found")
