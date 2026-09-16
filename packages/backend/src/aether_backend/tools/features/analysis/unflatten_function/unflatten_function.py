from pathlib import Path
from typing import Any

from aether_backend.forwarded_rpc import (
    get_data_at_address,
    get_function_pseudocode,
    get_local_variables,
    get_xrefs_to,
)
from aether_backend.utils.effect import Program, Return
from aether_backend.utils.stream_tool_logs import stream_tool_logs
from aether_backend.utils.subagent import (
    SubagentToolDependencies,
    build_subagent_tool,
)
from aether_utils.api_client import (
    OpenAIGateway,
)
from aether_utils.config import get_config
from aether_utils.get_content import get_content
from agents import Agent, Runner

SYSTEM_PROMPT = get_content(Path(__file__).parent, "prompt.md")


async def unflatten(service: Any, function_name: str, custom_prompt: str | None) -> Program:
    config = get_config()
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
                    get_xrefs_to,
                ],
            )
        ),
    )

    result = Runner.run_streamed(
        agent,
        context=SubagentToolDependencies(service),
        input=f"Deobfuscate the function {function_name}. Return the deobfuscated pseudocode.\n{custom_prompt}",
        max_turns=None,
    )

    async for log in stream_tool_logs(result):
        yield log

    yield Return(result.final_output)
