import asyncio
from itertools import chain
from pathlib import Path

from aether_backend.forwarded_rpc import (
    get_data_at_address,
    get_function_pseudocode,
    get_functions_called_recursively,
    get_local_variables,
)
from aether_backend.utils.get_rpc_service import AnyService
from aether_backend.utils.subagent import SubagentToolDependencies, build_subagent_tool
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


class EvaluateIDBTask(
    Task[[AnyService, BenchmarkConfig, BenchmarkSchema], BenchmarkSchemaWithResults]
):
    def __init__(self) -> None:
        super().__init__()
        self._run_handle: asyncio.Task[list[AgentRunResult]] | None = None

    async def start(
        self, service: AnyService, config: BenchmarkConfig, benchmark: BenchmarkSchema
    ) -> BenchmarkSchemaWithResults:
        model = build_model(config)
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

        constructed_prompts = (
            [
                f"""# Rubric: {rubric.name}
        ## Description
        {rubric.description or "No description provided."}

        ## Criterion
        {criterion}

        Use the available evidence to determine whether this criterion is satisfied.
        """
                for criterion in rubric.criteria
            ]
            for rubric in benchmark.rubrics
        )

        prompts = list(chain.from_iterable(constructed_prompts))

        runner = ParallelRunner(agent=agent, prompts=prompts)
        self._run_handle = asyncio.create_task(
            runner.run_all(context=SubagentToolDependencies(service=service))
        )

        results = await self._run_handle

        # reconstruct the results into a BenchmarkSchema extension with the results of the evaluation
        return reconstruct_results(benchmark, results)

    async def cancel(self) -> None:
        if self._run_handle is not None:
            self._run_handle.cancel()
