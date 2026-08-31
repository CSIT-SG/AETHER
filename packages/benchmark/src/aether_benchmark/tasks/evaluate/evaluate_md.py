import asyncio
from itertools import chain
from pathlib import Path

from aether_benchmark.cli import BenchmarkConfig
from aether_benchmark.tasks.parse_benchmark.models import BenchmarkSchema
from aether_benchmark.utils.task import Task
from aether_utils.get_content import get_content
from agents import Agent

from .models import (
    AgentRunResult,
    BenchmarkSchemaWithResults,
)
from .utils import ParallelRunner, build_model, reconstruct_results


class EvaluateMDTask(Task[[BenchmarkConfig, BenchmarkSchema, str], BenchmarkSchemaWithResults]):
    """Evaluate a single rubric entry against supplied information/evidence."""

    def __init__(self) -> None:
        super().__init__()
        self._run_handle: asyncio.Task[list[AgentRunResult]] | None = None

    async def start(
        self, config: BenchmarkConfig, benchmark: BenchmarkSchema, evidence: str
    ) -> BenchmarkSchemaWithResults:
        model = build_model(config)
        agent = Agent(
            name="MD Grading Agent",
            instructions=get_content(Path(__file__).parent, "md_evaluate_prompt.md"),
            model=model,
        )

        constructed_prompts = (
            [
                f"""# Rubric: {rubric.name}
        ## Description

        {rubric.description or "No description provided."}

        ## Criterion

        {criterion}

        ## Chatbot conversation transcript

        {evidence}

        Determine whether the chatbot's final answer satisfies the criterion.
        """
                for criterion in rubric.criteria
            ]
            for rubric in benchmark.rubrics
        )

        prompts = list(chain.from_iterable(constructed_prompts))

        runner = ParallelRunner(agent=agent, prompts=prompts)
        self._run_handle = asyncio.create_task(runner.run_all())

        results = await self._run_handle

        # reconstruct the results into a BenchmarkSchema extension with the results of the evaluation
        return reconstruct_results(benchmark, results)

    async def cancel(self) -> None:
        if self._run_handle is not None:
            self._run_handle.cancel()
