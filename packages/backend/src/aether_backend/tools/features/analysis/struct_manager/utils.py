from collections.abc import Awaitable, Callable, Iterable
from pathlib import Path
from typing import Any

from aether_backend.utils.subagent import (
    build_subagent_tool,
)
from aether_utils.api_client import (
    OpenAIGateway,
)
from aether_utils.config import get_config
from aether_utils.get_content import get_content
from agents import Agent, ModelSettings


def create_agent(tool_list: Iterable[Callable[..., Awaitable[Any]]]) -> Agent:
    config = get_config()
    prompt = get_content(Path(__file__).parent, "struct_creator_instructions.md")
    agent = Agent(
        name="struct manager",
        model=OpenAIGateway().get_model(
            model_name=config.subagents.annotator_model if config.subagents else None,
            feature="struct manager",
        ),
        instructions=prompt,
        tools=list(
            map(
                build_subagent_tool,
                tool_list,
            )
        ),
        model_settings=ModelSettings(parallel_tool_calls=False),
    )
    return agent
