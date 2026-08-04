from pathlib import Path
from typing import Any

from aether_backend.forwarded_rpc import (
    get_data_at_address,
    get_function_pseudocode,
    get_local_variables,
    rename_function,
    rename_local_variable,
    set_inline_comment,
    set_summary_comment,
)
from aether_backend.utils.effect import Log, Program, Return
from aether_backend.utils.subagent import (
    SubagentToolDependencies,
    build_subagent_tool,
)
from aether_utils.api_client import (
    OpenAIGateway,
)
from aether_utils.config import get_config
from aether_utils.get_content import get_content
from agents import Agent, Runner

config = get_config()

INSTRUCTIONS = get_content(Path(__file__).parent, "prompt.md")


async def test(service: Any, rpc_tool: str, **kwargs: Any) -> Program:
    agent = Agent(
        name="RPC Tester",
        model=OpenAIGateway().get_model(
            feature="test",
        ),
        instructions=INSTRUCTIONS,
        tools=list(
            map(
                build_subagent_tool,
                [
                    get_data_at_address,
                    get_function_pseudocode,
                    get_local_variables,
                    rename_function,
                    set_inline_comment,
                    set_summary_comment,
                    rename_local_variable,
                ],
            )
        ),
    )
    yield Log(f"Testing {rpc_tool} at address: {kwargs}")

    result = Runner.run_streamed(
        agent,
        context=SubagentToolDependencies(service),
        input=f"Call {rpc_tool} using these arguments: {kwargs}.",
    )

    async for event in result.stream_events():
        yield Log(str(event))

    yield Return(None)
