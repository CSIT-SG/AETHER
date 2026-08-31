"""
Usage:
    python -m aether_benchmark --idb <path> --rubric <path> --api-key <key> --ida-dir <dir>
    python -m aether_benchmark --doc <transcript.md> --rubric <path> --api-key <key>
"""

import asyncio
import json
import logging
from typing import cast

from aether_benchmark.tasks.evaluate import (
    EvaluateIDBTask,
    EvaluateMDTask,
)
from aether_benchmark.tasks.evaluate.models import BenchmarkSchemaWithResults
from aether_benchmark.tasks.parse_benchmark.models import BenchmarkSchema
from aether_benchmark.tasks.print_results import PrintResultsTask
from aether_benchmark.tasks.start_rpc_server import StartRPCServerTask
from aether_benchmark.utils.task import Run
from aether_utils.logger import get_logger
from agents import set_tracing_disabled
from rich.console import Console

from .cli import BenchmarkConfig, DocTarget, IdbTarget, get_config
from .tasks import ParseBenchmarkTask

logger = get_logger("AETHER_BENCHMARK.RPC", logging.INFO)


async def _run_eval(args: BenchmarkConfig, schema: BenchmarkSchema) -> BenchmarkSchemaWithResults:
    """Run evaluation for the given benchmark config and schema."""

    match args.target.name:
        case "idb":
            assert isinstance(args.target, IdbTarget)
            async with Run(StartRPCServerTask)(
                args.target.ida_dir, str(args.target.idb)
            ) as rpc_handle:
                logger.debug("Starting RPC handle")
                service = await rpc_handle
                logger.debug(service)
                logger.debug("Completed RPC handle")
                return await Run(EvaluateIDBTask)(service, args, schema)
        case "doc":
            assert isinstance(args.target, DocTarget)
            transcript = args.target.doc.read_text(encoding="utf-8")  # io error will propagate

            return await Run(EvaluateMDTask)(args, schema, transcript)
        case _:
            raise RuntimeError(
                f"Invariant: unknown kind {args.target.name!r} (should be 'idb' or 'doc')"
            )
    raise RuntimeError("Unreachable code reached in _run_eval")


async def _run_benchmark(
    args: BenchmarkConfig,
) -> BenchmarkSchemaWithResults:
    """Acquire evidence for the selected harness and run the grading loop."""
    schema = cast(BenchmarkSchema, await Run(ParseBenchmarkTask)(BenchmarkSchema, args.rubric))
    results = await _run_eval(args, schema)
    return results


async def _async_main() -> None:
    set_tracing_disabled(True)
    args = get_config()
    with Console().status("[bold cyan]Evaluating rubric...[/bold cyan]"):
        results = await _run_benchmark(args)

    output = results.model_dump()
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(output, indent=2), encoding="utf-8")
    if args.json_output:
        print(json.dumps(output, indent=2))
        return

    await Run(PrintResultsTask)(args, results)


def main() -> None:
    """Run the benchmark CLI."""
    asyncio.run(_async_main())


if __name__ == "__main__":
    main()
