import asyncio
from typing import Any

from aether_backend.utils.force_structured_output import force_structured_output
from agents import (
    Agent,
    OpenAIChatCompletionsModel,
    RunConfig,
    Runner,
)
from openai import AsyncOpenAI

from aether_benchmark.cli import BenchmarkConfig
from aether_benchmark.tasks.parse_benchmark.models import BenchmarkSchema

from .models import (
    AgentRunResult,
    BenchmarkSchemaWithResults,
    CriterionResult,
    CriterionWithResult,
    RubricEntryWithResults,
)


def build_model(config: BenchmarkConfig) -> OpenAIChatCompletionsModel:
    """Build an OpenAIChatCompletionsModel from the benchmark config."""

    client = AsyncOpenAI(api_key=config.api_key, base_url=config.base_url)
    return OpenAIChatCompletionsModel(model=config.model, openai_client=client)


class ParallelRunner:
    """A Runner that runs agent completions in parallel."""

    def __init__(self, *, agent: Agent, prompts: list[str], limit: int = 5) -> None:
        self.agent = agent
        self.prompts = prompts

        # we dont want to be rate limited by the number of concurrent requests,
        # so we limit the number of concurrent completions to a reasonable number
        self._sem = asyncio.Semaphore(limit)
        self._tasks: list[asyncio.Task[AgentRunResult]] = []

    async def _run_one(
        self,
        prompt: str,
        *,
        context: dict[str, object] | None = None,
        max_turns: int = 20,
        run_config: RunConfig | None = RunConfig(tracing_disabled=True),
    ) -> AgentRunResult:
        async with self._sem:
            try:
                result = await Runner.run(
                    self.agent, prompt, context=context, max_turns=max_turns, run_config=run_config
                )
                cr = await force_structured_output(self.agent, CriterionResult, result)
                return {"success": True, "data": cr}
            except Exception as e:
                return {"success": False, "error": str(e)}

    async def run_all(
        self,
        *,
        context: Any = None,
        max_turns: int = 20,
        run_config: RunConfig | None = None,
    ) -> list[AgentRunResult]:
        self._tasks = [
            asyncio.create_task(
                self._run_one(prompt, context=context, max_turns=max_turns, run_config=run_config)
            )
            for prompt in self.prompts
        ]
        results = await asyncio.gather(*self._tasks)
        return results

    def cancel(self) -> None:
        for t in self._tasks:
            t.cancel()


def reconstruct_results(
    benchmark: BenchmarkSchema, results: list[AgentRunResult]
) -> BenchmarkSchemaWithResults:
    """Reconstruct the results into a BenchmarkSchema extension with the results of the evaluation."""
    results_iter = iter(results)

    benchmark_with_results = BenchmarkSchemaWithResults(
        name=benchmark.name,
        version=benchmark.version,
        description=benchmark.description,
        rubrics=[
            RubricEntryWithResults(
                name=rubric.name,
                description=rubric.description,
                weight=rubric.weight,
                criteria=[
                    CriterionWithResult(criterion=criterion, result=next(results_iter))
                    for criterion in rubric.criteria
                ],
            )
            for rubric in benchmark.rubrics
        ],
    )

    return benchmark_with_results
