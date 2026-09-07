from collections.abc import Awaitable, Callable, Iterable
from typing import Any, cast

from aether_backend.forwarded_rpc import get_function_by_address, get_local_variables, get_xrefs_to
from aether_backend.utils.effect import Log, Program
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
    async for event in result.stream_events():
        if event.type != "run_item_stream_event":
            continue

        run_item = event.item
        if run_item.type == "tool_call_item":
            args = getattr(run_item.raw_item, "arguments", "")
            yield Log(f"{run_item.tool_name}({args})")

        elif run_item.type == "tool_call_output_item":
            yield Log(str(run_item.output))


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


async def resolve_xrefs(svc: Any, function_address: HexAddress, var_name: str) -> XrefsResult:
    xrefs = await get_xrefs_to(svc, location=function_address, variable=var_name)

    if xrefs.success is False:
        raise RuntimeError(f"Failed to get xrefs {xrefs.result}")

    return xrefs.result
