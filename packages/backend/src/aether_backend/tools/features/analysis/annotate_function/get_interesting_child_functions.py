from pathlib import Path
from typing import Any, cast

from aether_backend.forwarded_rpc import (
    get_data_at_address,
    get_function_pseudocode,
    get_functions_called_recursively,
)
from aether_backend.utils.force_structured_output import force_structured_output
from aether_backend.utils.subagent import (
    SubagentToolDependencies,
    build_subagent_tool,
)
from aether_backend.utils.validation import HexAddress
from aether_utils.api_client import OpenAIGateway
from aether_utils.config import get_config
from aether_utils.get_content import get_content
from agents import Agent, Runner

from .types import InterestingFunc

CONFIG = get_config()
SYSTEM_PROMPT = get_content(Path(__file__).parent, "interesting_children_prompt.md")


async def get_interesting_child_functions(
    service: Any, function_address: HexAddress
) -> list[InterestingFunc]:
    """
    Get interesting child functions called by the function at the given address.
    """

    agent = Agent(
        name="interesting_function_finder",
        model=OpenAIGateway().get_model(
            model_name=CONFIG.subagents.gatherer_model if CONFIG.subagents else None,
            feature="find_interesting_child_functions",
        ),
        instructions=SYSTEM_PROMPT,
        tools=list(
            map(
                build_subagent_tool,
                [get_data_at_address, get_function_pseudocode, get_functions_called_recursively],
            )
        ),
    )

    result = await Runner.run(
        agent,
        context=SubagentToolDependencies(service),
        input=f"Gather interesing and relevant child functions called in {function_address}.",
        max_turns=1000,
    )

    return cast(
        list[InterestingFunc],
        await force_structured_output(agent, list[InterestingFunc], result),
    )
