from typing import Any

from aether_backend.utils.effect import Log, Program, Return
from aether_backend.utils.subagent import (
    InternalToolDependencies,
    OpenAIGateway,
    SubagentTool,
    internal_tool_registry,
)
from aether_utils.config import get_config
from agents import Agent, Runner

config = get_config()


async def annotate(service: Any, function_address: str | int) -> Program:
    agent = Agent(
        name="Annotator",
        model=OpenAIGateway().get_model(
            model_name=config.subagents.annotator_model if config.subagents else None,
            feature="annotator",
        ),
        instructions="""
        You are a skilled and meticulous reverse engineer operating in IDA Pro. You are terse and concise and think carefully and at length before acting.
Your task is to analyse a function from a given binary.

You must now use this context of the call tree and the psuedocode of callees to make the psuedocode more useful and informative for the human reverse engineer using IDA Pro.

You need to analyse the given portion of the program as a whole, tracing code paths and analysing the functions and logic carefully to make intelligent and evidence-backed annotations to the psuedocode.

For instance:

If a variable is called `v1` and you rename it to `var1`, that has zero value-add.
But if, for instance, you saw a function passing arguments to a CreateProcessW through intermediary functions, it may be sensible to rename the variables along the way to their corresponding ones in CreateProcessW.

For another example:
It's possible for some binaries to roll their own cryptography. If through your analysis you determine that a function may be performing certain recognisable encryption or decryption, appropriate annotations may follow.

My examples are solely meant for guidance. You should take an exploratory approach in your thought process to perform substantial and meaningful analysis of the segment of the program given to you to make insightful improvements to the psuedocode.
        """,
        tools=internal_tool_registry.get_tools(SubagentTool.ANNOTATOR),
    )
    yield Log(f"Annotating function at address: {function_address}, tools: {agent.tools}")

    result = Runner.run_streamed(
        agent,
        context=InternalToolDependencies(service),
        input=f"Analyze the function at address {function_address} and provide annotations for the psuedocode.",
    )

    async for event in result.stream_events():
        if event.type != "run_item_stream_event":
            continue

        item = event.item
        if item.type == "tool_call_output_item":
            yield Log(f"tool output: {item.output}")

    yield Return(None)
