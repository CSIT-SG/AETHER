from functools import partial
from typing import Any

from aether_backend.utils.subagent import (
    OpenAIGateway,
    SubagentTool,
    get_subagent_tools,
)
from aether_backend.utils.effect import Log, Program, Return
from aether_utils.config import get_config
from agents import Agent

config = get_config()


async def annotate(service: Any, function_address: str | int) -> Program:
    agent = Agent(
        name="Annotator",
        model=OpenAIGateway().get_model(
            model_name=config.subagents.annotator_model if config.subagents else None,
            feature="annotator",
        ),
        tools=[partial(tool, service) for tool in get_subagent_tools(SubagentTool.ANNOTATOR)],  # type: ignore
    )
    yield Log(f"Annotating function at address: {function_address}, tools: {agent.tools}")
    yield Return(None)
