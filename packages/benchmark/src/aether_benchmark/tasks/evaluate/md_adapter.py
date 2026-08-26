from pathlib import Path
from typing import TypedDict

from aether_backend.utils.get_rpc_service import AnyService
from aether_utils.get_content import get_content
from agents import Agent, Runner

from .adapter import AgentAdapter


class MDPromptDependencies(TypedDict):
    rubric_name: str
    description: str
    transcript: str
    criterion: str


class MDAgentAdapter(AgentAdapter[MDPromptDependencies]):
    @staticmethod
    def build_agent(*, model: str) -> Agent:
        agent = Agent(
            name="MD Grading Agent",
            instructions=get_content(Path(__file__).parent, "md_evaluate_prompt.md"),
            model=model,
        )
        return agent

    @staticmethod
    async def run_agent(
        *, agent: Agent, service: AnyService, prompt_dependencies: MDPromptDependencies
    ) -> str:
        # service is not used because the MD evidence type does not require any additional context for the agent to evaluate the criterion.

        prompt = f"""# Rubric: {prompt_dependencies["rubric_name"]}
## Description

{prompt_dependencies["description"]}

## Criterion

{prompt_dependencies["criterion"]}

## Chatbot conversation transcript

{prompt_dependencies["transcript"]}

Determine whether the chatbot's final answer satisfies the criterion.
"""
        res = await Runner.run(agent, input=prompt, max_turns=20, run_config=None)
        return res.final_output if res.final_output is not None else ""
