from aether_backend.utils.effect import Program, Return
from aether_backend.utils.internal_tools import (
    SubagentTool,
    get_subagent_tools,
)
from aether_backend.utils.agent_orchestrator import OpenAIGateway
from agents import Agent, Runner
from aether_utils.config import get_config

config = get_config()


async def annotate_function(function_address: str | int) -> Program:
    agent = Agent(
        name="Annotator",
        model=OpenAIGateway().get_model(
            model_name=config.subagents.annotator_model if config.subagents else None,
            feature="annotator",
        ),
        tools=get_subagent_tools(SubagentTool.ANNOTATOR),
    )
    yield Return(None)
