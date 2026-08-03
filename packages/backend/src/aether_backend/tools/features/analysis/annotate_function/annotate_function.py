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
from aether_rpc.capabilities.types import FunctionTreeResult
from aether_utils.api_client import (
    OpenAIGateway,
)
from aether_utils.config import get_config
from aether_utils.get_content import get_content
from agents import Agent, ModelSettings, Runner

from .utils import iter_addresses

SYSTEM_PROMPT = get_content(Path(__file__).parent, "annotate_function_prompt.md")

config = get_config()


async def annotate(service: Any, funcs: FunctionTreeResult, custom_prompt: str | None) -> Program:
    base_addr = funcs["root"]["address"]
    addresses = iter_addresses(funcs["root"])
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

    result = Runner.run_streamed(
        agent,
        context=SubagentToolDependencies(service),
        input=(
            f"Analyze the following functions and provide annotations for the psuedocode"
            f"{base_addr} is the base function, your main goal is to figure out what this does and annotate it"
            f"Here are the functions that it calls. These will be useful for determining the purpose of the base function, analyse these too: \n{funcs}\n{custom_prompt}"
        ),
        max_turns=100000,
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

    try:
        for address in addresses:
            service.refresh_pseudocode(function_address=address)
        service.refresh_pseudocode(function_address=base_addr)
    except Exception as e:
        yield Return(e)

    yield Return(result.final_output)
