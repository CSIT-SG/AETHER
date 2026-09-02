"""
Usage:
    python -m aether_benchmark --idb <path> --rubric <path> --api-key <key> --ida-dir <dir>
    python -m aether_benchmark --doc <transcript.md> --rubric <path> --api-key <key>
"""

import asyncio
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

from .cli import BenchmarkConfig, DocTarget, IdbTarget, get_config
from .tasks import ParseBenchmarkTask

logger = get_logger("AETHER_BENCHMARK.RPC", logging.INFO)


async def _run_eval(args: BenchmarkConfig, schema: BenchmarkSchema) -> BenchmarkSchemaWithResults:
    """Run evaluation for the given benchmark config and schema."""
    match args.target:
        case IdbTarget(ida_dir=ida_dir, idb=idb):
            async with Run(StartRPCServerTask)(ida_dir, str(idb)) as rpc_handle:
                return await Run(EvaluateIDBTask)(await rpc_handle, args, schema)
        case DocTarget(doc=doc):
            return await Run(EvaluateMDTask)(args, schema, doc.read_text(encoding="utf-8"))
        case _:
            raise RuntimeError(f"Invariant: unknown target {args.target!r}")
    raise RuntimeError("Unreachable code.")


async def _async_main() -> None:
    set_tracing_disabled(True)

    args = get_config()
    schema = cast(BenchmarkSchema, await Run(ParseBenchmarkTask)(BenchmarkSchema, args.rubric))

    results = await _run_eval(args, schema)
    await Run(PrintResultsTask)(args, results)


def main() -> None:
    """Run the benchmark CLI."""
    asyncio.run(_async_main())


if __name__ == "__main__":
    main()
