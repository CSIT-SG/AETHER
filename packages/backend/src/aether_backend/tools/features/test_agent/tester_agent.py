from pathlib import Path
from typing import Any

from aether_backend.utils.effect import Log, Program, Return
from aether_backend.utils.get_content import get_content
from aether_backend.utils.subagent import (
    InternalToolDependencies,
    OpenAIGateway,
    SubagentTool,
    internal_tool_registry,
)
from aether_utils.config import get_config
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
        tools=internal_tool_registry.get_tools(SubagentTool.ANNOTATOR),
    )
    yield Log(f"Testing {rpc_tool} at address: {kwargs}")

    result = Runner.run_streamed(
        agent,
        context=InternalToolDependencies(service),
        input=f"Call {rpc_tool} using these arguments: {kwargs}.",
    )

    async for event in result.stream_events():
        yield Log(str(event))

    yield Return(None)
