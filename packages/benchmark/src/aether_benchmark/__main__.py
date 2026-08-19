from pathlib import Path

from aether_benchmark.tasks.parse_benchmark.models import RubricsSchema
from aether_benchmark.utils.task import Run

from .tasks import EvaluateTask, ParseBenchmarkTask, StartRPCServerTask


async def main() -> None:
    # stupid values to give u an idea of how to use the tasks
    benchmark = await Run(ParseBenchmarkTask)(RubricsSchema, Path("benchmark.yaml"))

    # run in the background, we dont need to await it here because we are not using the result
    Run(StartRPCServerTask)(Path("ida_dir"))

    res = await Run(EvaluateTask)(benchmark)

    # pretty print the result here
