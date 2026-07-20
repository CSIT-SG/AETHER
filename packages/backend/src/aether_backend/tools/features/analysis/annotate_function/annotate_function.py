from pathlib import Path
from typing import Any

from aether_backend.forwarded_rpc import (
    get_data_at_address,
    get_function_pseudocode,
    get_local_variables,
    rename_function,
    rename_local_variable,
    set_comment,
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
from agents import Agent, ModelSettings, Runner

from .types import InterestingFunc

config = get_config()
SYSTEM_PROMPT = get_content(Path(__file__).parent, "prompt.md")


async def annotate(
    service: Any, funcs: list[InterestingFunc], custom_prompt: str | None
) -> Program:
    if config.backup:
        service.take_snapshot()
    yield Log(str(funcs))
    agent = Agent(
        name="Annotator",
        model=OpenAIGateway().get_model(
            model_name=config.subagents.annotator_model if config.subagents else None,
            feature="annotator",
        ),
        instructions=SYSTEM_PROMPT,
        tools=list(
            map(
                build_subagent_tool,
                [
                    get_data_at_address,
                    get_function_pseudocode,
                    get_local_variables,
                    rename_function,
                    set_comment,
                    rename_local_variable,
                ],
            )
        ),
        model_settings=ModelSettings(parallel_tool_calls=False),
    )

    if custom_prompt is None:
        custom_prompt = ""

    result = Runner.run_streamed(
        agent,
        context=SubagentToolDependencies(service),
        input=(
            f"Analyze the following functions and provide annotations for the psuedocode"
            f"{funcs}\n{custom_prompt}"
        ),
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

    addresses = [item["address"] for item in funcs]

    for address in addresses:
        service.refresh_pseudocode(function_address=address)

    yield Return(result.final_output)
