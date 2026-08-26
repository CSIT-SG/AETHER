from collections.abc import Awaitable, Callable, Iterable
from typing import Any

from aether_backend.utils.effect import Program
from aether_backend.utils.subagent import (
    SubagentToolDependencies,
    build_subagent_tool,
)
from aether_rpc.capabilities.types import XrefsResult
from aether_utils.api_client import (
    OpenAIGateway,
)
from aether_utils.config import get_config
from agents import Agent, ModelSettings, Runner

from .types import StructOperation


def create_agent(tool_list: Iterable[Callable[..., Awaitable[Any]]], system_prompt: str) -> Agent:
    config = get_config()
    agent = Agent(
        name="struct manager",
        model=OpenAIGateway().get_model(
            model_name=config.subagents.annotator_model if config.subagents else None,
            feature="struct manager",
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
    var_name: str,
    xrefs: XrefsResult,
    custom_prompt: str | None = None,
) -> Program:
    result = Runner.run_streamed(
        agent,
        context=SubagentToolDependencies(svc),
        input=(
            f"{operation} the struct representative of {var_name}"
            f"For added context you are to take a look at {xrefs}. These are the cross references to {var_name}"
            f"{custom_prompt}"
        ),
        max_turns=100000,
    )

    return result.final_output
