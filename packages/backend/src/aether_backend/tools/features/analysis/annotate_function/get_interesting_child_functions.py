from pathlib import Path
from typing import Any

from aether_backend.forwarded_rpc import (
    get_data_at_address,
    get_function_pseudocode,
    get_functions_called_recursively,
)
from aether_backend.utils.get_content import get_content
from aether_backend.utils.subagent import (
    OpenAIGateway,
    SubagentToolDependencies,
    build_subagent_tool,
)
from aether_backend.utils.validation import HexAddress
from aether_utils.config import get_config
from agents import Agent, ModelSettings, Runner, function_tool
from agents.agent import StopAtTools

from .types import InterestingFunc

CONFIG = get_config()
SYSTEM_PROMPT = get_content(Path(__file__).parent, "interesting_children_prompt.md")
TOOL_NAME = "format_outputs"


async def get_interesting_child_functions(
    service: Any, function_address: HexAddress, custom_prompt: str | None
) -> list[InterestingFunc]:
    """
    should return  list[InterestingFunc]

    InterestingFunc is a dict of shape {address: HexAddress, reason: str}
    """
    if CONFIG.backup:
        service.take_snapshot()

    captured_output: list[InterestingFunc] = []

    # Ensures structured outputs, stored in captured_output
    @function_tool(name_override=TOOL_NAME, description_override="formats outputs")
    async def format_output(args: list[InterestingFunc]) -> None:
        captured_output.extend(args)
        return None

    agent = Agent(
        name="interesting_function_finder",
        model=OpenAIGateway().get_model(
            model_name=CONFIG.subagents.gatherer_model if CONFIG.subagents else None,
            feature="find_interesting_child_functions",
        ),
        instructions=SYSTEM_PROMPT,
        tools=[
            *map(
                build_subagent_tool,
                [get_data_at_address, get_function_pseudocode, get_functions_called_recursively],
            ),
            format_output,
        ],
        tool_use_behavior=StopAtTools(stop_at_tool_names=[TOOL_NAME]),
        model_settings=ModelSettings(tool_choice="required"),
    )

    if custom_prompt is None:
        custom_prompt = ""

    result = await Runner.run(
        agent,
        context=SubagentToolDependencies(service),
        input=f"Gather interesing and relevant child functions called in {function_address} \n{custom_prompt}",
        max_turns=None,
    )
    print(result.final_output)
    print([t.name for t in agent.tools])
    try:
        return captured_output
    except Exception as e:
        raise RuntimeError("Model returned invalid value. Please try again.") from e
