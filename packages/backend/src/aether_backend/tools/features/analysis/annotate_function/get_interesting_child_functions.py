from pathlib import Path
from typing import Any

from aether_backend.forwarded_rpc import (
    get_data_at_address,
    get_function_pseudocode,
    get_functions_called_recursively,
)
from aether_backend.utils.subagent import (
    SubagentToolDependencies,
    build_subagent_tool,
)
from aether_backend.utils.validation import HexAddress
from aether_utils.api_client import (
    OpenAIGateway,
)
from aether_utils.config import get_config
from aether_utils.get_content import get_content
from agents import Agent, Runner, function_tool
from agents.agent import StopAtTools

from .types import InterestingFunc

CONFIG = get_config()
SYSTEM_PROMPT = get_content(Path(__file__).parent, "interesting_children_prompt.md")


async def get_interesting_child_functions(
    service: Any, function_address: HexAddress
) -> list[InterestingFunc]:
    """
    Get interesting child functions called by the function at the given address.
    """

    captured_output: list[InterestingFunc] = []

    # Ensures structured outputs, stored in captured_output
    @function_tool
    async def submit_output(args: list[InterestingFunc]) -> None:
        """Submit the interesting child functions found by the model."""
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
            submit_output,
        ],
        tool_use_behavior=StopAtTools(stop_at_tool_names=[submit_output.name]),
    )

    result = await Runner.run(
        agent,
        context=SubagentToolDependencies(service),
        input=f"Gather interesing and relevant child functions called in {function_address}.",
        max_turns=1000,
    )

    _max = 3
    while len(captured_output) == 0 and _max > 0:
        # Model ignored the tool-call requirement
        result = await Runner.run(
            agent,
            context=SubagentToolDependencies(service),
            input=result.to_input_list()
            + [
                {
                    "role": "user",
                    "content": "You did not call submit_output. You must call it now with your findings.",
                }
            ],
            max_turns=None,
        )
        _max -= 1

    try:
        return captured_output
    except Exception as e:
        raise RuntimeError(f"Model returned invalid value. Please try again. \nerror: {e}") from e
