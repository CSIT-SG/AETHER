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
SYSTEM_PROMPT = get_content(Path(__file__).parent, "prompt.md")
SYSTEM_INPUT = get_content(Path(__file__).parent, "input.md")


async def annotate(service: Any, function_address: str | int) -> Program:
    agent = Agent(
        name="Annotator",
        model=OpenAIGateway().get_model(
            model_name=config.subagents.annotator_model if config.subagents else None,
            feature="annotator",
        ),
        instructions=SYSTEM_PROMPT,
        tools=internal_tool_registry.get_tools(SubagentTool.ANNOTATOR),
    )

    result = Runner.run_streamed(
        agent,
        context=InternalToolDependencies(service),
        input=SYSTEM_INPUT.format(function_address=function_address),
        max_turns=None,
    )

    async for event in result.stream_events():
        if event.type == "run_item_stream_event":
            RunItem = event.item
            if RunItem.type == "tool_call_item":
                yield Log(str(RunItem.tool_name))
                if hasattr(RunItem.raw_item, "arguments"):
                    yield Log(str(RunItem.raw_item.arguments))  # type: ignore

            elif RunItem.type == "tool_call_output_item":
                yield Log(str(RunItem.output))
            elif RunItem.type == "reasoning_item":
                content = RunItem.raw_item.content
                if content is not None:
                    yield Log(content[0].text)
        continue

    service.refresh_pseudocode(function_address=function_address)

    yield Return(result.final_output)
