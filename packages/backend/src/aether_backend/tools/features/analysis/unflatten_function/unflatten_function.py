from pathlib import Path
from typing import Any

from aether_backend.forwarded_rpc import (
    get_data_at_address,
    get_function_pseudocode,
    get_local_variables,
)
from aether_backend.utils.effect import Log, Program, Return
from aether_backend.utils.get_content import get_content
from aether_backend.utils.subagent import (
    SubagentToolDependencies,
    build_subagent_tool,
)
from aether_utils.api_client import (
    OpenAIGateway,
)
from aether_utils.config import get_config
from agents import Agent, Runner

config = get_config()
SYSTEM_PROMPT = get_content(Path(__file__).parent, "prompt.md")


async def unflatten(
    service: Any, function_address: str | int, custom_prompt: str | None
) -> Program:

    agent = Agent(
        name="Unflattener",
        model=OpenAIGateway().get_model(
            model_name=config.subagents.unflattener_model if config.subagents else None,
            feature="unflattener",
        ),
        instructions=SYSTEM_PROMPT,
        tools=list(
            map(
                build_subagent_tool,
                [
                    get_data_at_address,
                    get_function_pseudocode,
                    get_local_variables,
                ],
            )
        ),
    )

    if custom_prompt is None:
        custom_prompt = ""
    result = Runner.run_streamed(
        agent,
        context=SubagentToolDependencies(service),
        input=f"Deobfuscate the function at address {function_address}. Return the deobfuscated pseudocode.\n{custom_prompt}",
        max_turns=None,
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

    yield Return(result.final_output)
