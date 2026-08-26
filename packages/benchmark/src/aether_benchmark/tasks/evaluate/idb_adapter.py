from pathlib import Path
from typing import TypedDict

from aether_backend.forwarded_rpc import (
    get_data_at_address,
    get_function_pseudocode,
    get_functions_called_recursively,
    get_local_variables,
)
from aether_backend.utils.get_rpc_service import AnyService
from aether_backend.utils.subagent import SubagentToolDependencies, build_subagent_tool
from aether_utils.get_content import get_content
from agents import Agent, Runner

from .adapter import AgentAdapter


class IDBPromptDependencies(TypedDict):
    rubric_name: str
    description: str
    criterion: str


class IDBAgentAdapter(AgentAdapter[IDBPromptDependencies]):
    @staticmethod
    def build_agent(*, model: str) -> Agent:
        agent = Agent(
            name="IDB Grading Agent",
            instructions=get_content(Path(__file__).parent, "idb_evaluate_prompt.md"),
            model=model,
            tools=[
                *map(
                    build_subagent_tool,
                    [
                        get_data_at_address,
                        get_function_pseudocode,
                        get_local_variables,
                        get_functions_called_recursively,
                    ],
                )
            ],
        )
        return agent

    @staticmethod
    async def run_agent(
        *, agent: Agent, service: AnyService, prompt_dependencies: IDBPromptDependencies
    ) -> str:
        prompt = f"""
# Rubric: {prompt_dependencies["rubric_name"]}
## Description

{prompt_dependencies["description"]}

## Criterion

{prompt_dependencies["criterion"]}

Use the available evidence to determine whether this criterion is satisfied.
"""
        res = await Runner.run(
            agent,
            input=prompt,
            context=SubagentToolDependencies(service=service),
            max_turns=20,
            run_config=None,
        )
        return res.final_output if res.final_output is not None else ""
