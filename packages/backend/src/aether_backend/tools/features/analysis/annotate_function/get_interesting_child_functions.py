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
from aether_utils.config import get_config
from agents import Agent, ModelSettings, Runner, function_tool
from agents.agent import StopAtTools

from .types import InterestingFunc_TD

CONFIG = get_config()
SYSTEM_PROMPT = get_content(Path(__file__).parent, "interesting_children_prompt.md")
TOOL_NAME = "format_outputs"


class _Validation:
    def __init__(self) -> None:
        self._output: list[InterestingFunc_TD] = []

    @function_tool(name_override=TOOL_NAME, description_override="formats outputs")
    async def validate_interesting_functions(self, args: list[InterestingFunc_TD]) -> None:
        print(args)
        self._output = args
        return None


async def get_interesting_child_functions(
    service: Any, function_address: str | int, custom_prompt: str | None
) -> list[InterestingFunc_TD]:
    # should return Array<{ address: number; reason: string }>
    if CONFIG.backup:
        service.take_snapshot()

    output = _Validation()

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
            output.validate_interesting_functions,
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
    print(output._output)
    try:
        return output._output

    except Exception as e:
        raise RuntimeError("Model returned invalid value. Please try again.") from e
    """
        result_json = cast(list[Any], json.loads(result.final_output))
        result_json.insert(0, {"address": function_address, "reason": "This function is the base function, the main goal of the analysis is to figure out what this"})
        model = list[InterestingFunc_TD].model_validate(result_json)
        return model
    """
