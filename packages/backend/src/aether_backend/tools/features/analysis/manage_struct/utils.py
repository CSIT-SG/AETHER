from collections.abc import Awaitable, Callable, Iterable
from typing import Any, cast

from aether_backend.forwarded_rpc import get_function_by_address, get_local_variables
from aether_backend.utils.effect import Program
from aether_backend.utils.stream_tool_logs import stream_tool_logs
from aether_backend.utils.subagent import (
    SubagentToolDependencies,
    build_subagent_tool,
)
from aether_backend.utils.validation import HexAddress
from aether_utils.api_client import (
    OpenAIGateway,
)
from agents import Agent, ModelSettings, Runner


def create_agent(
    *,
    tool_list: Iterable[Callable[..., Awaitable[Any]]],
    system_prompt: str,
    name: str,
    model_name: str | None = None,
) -> Agent:
    agent = Agent(
        name=name,
        model=OpenAIGateway().get_model(
            model_name=model_name,
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
    user_prompt: str,
    custom_prompt: str | None = None,
) -> Program:
    if custom_prompt is None:
        custom_prompt = ""
    result = Runner.run_streamed(
        agent,
        context=SubagentToolDependencies(svc),
        input=user_prompt + custom_prompt,
        max_turns=100000,
    )
    async for log in stream_tool_logs(result):
        yield log


async def get_var_type(svc: Any, function_address: HexAddress, variable: str) -> str:
    func = await get_function_by_address(service=svc, address=function_address)
    if func.success is False:
        raise RuntimeError(f"Unable to get function {function_address}")
    func_name = func.result["name"]
    lvars = await get_local_variables(svc, function_name=func_name)
    if lvars.success is False:
        raise RuntimeError("Unable to get local variables")
    for var in lvars.result:
        if var["name"] == variable:
            return cast(str, var["type"])
    raise RuntimeError(f"variable {variable} not found")
