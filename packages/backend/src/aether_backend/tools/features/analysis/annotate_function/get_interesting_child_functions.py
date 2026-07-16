import json
from pathlib import Path
from typing import Any, cast

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
from agents import Agent, Runner

from .models import InterestingFunctions

CONFIG = get_config()
SYSTEM_PROMPT = get_content(Path(__file__).parent, "interesting_children_prompt.md")


async def get_interesting_child_functions(
    service: Any, function_address: str | int, custom_prompt: str | None
) -> InterestingFunctions:
    # should return Array<{ address: number; reason: string }>
    if CONFIG.backup:
        service.take_snapshot()

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

    if custom_prompt is None:
        custom_prompt = ""

    result = await Runner.run(
        agent,
        context=SubagentToolDependencies(service),
        input=f"Gather interesing and relevant child functions called in {function_address} \n{custom_prompt}",
        max_turns=None,
    )

    try:
        result_json = cast(list[Any], json.loads(result.final_output))
        result_json.insert(0, {"address": function_address, "reason": "base function"})
        model = InterestingFunctions.model_validate(result_json)
        return model

    except Exception as e:
        raise RuntimeError("Model returned invalid value. Please try again.") from e
