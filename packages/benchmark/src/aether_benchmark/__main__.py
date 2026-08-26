"""
Usage:
    python -m aether_benchmark --idb <path> --rubric <path> --api-key <key> --ida-dir <dir>
    python -m aether_benchmark --doc <transcript.md> --rubric <path> --api-key <key>
"""

import asyncio
import json
from typing import cast

from aether_benchmark.tasks.evaluate import (
    EvaluateIDBTask,
    EvaluateMDTask,
)
from aether_benchmark.tasks.evaluate.models import BenchmarkSchemaWithResults
from aether_benchmark.tasks.parse_benchmark.models import BenchmarkSchema
from aether_benchmark.tasks.start_rpc_server import StartRPCServerTask
from aether_benchmark.utils.task import Run

from .cli import BenchmarkConfig, DocTarget, IdbTarget, get_config
from .tasks import ParseBenchmarkTask


async def _run_eval(args: BenchmarkConfig, schema: BenchmarkSchema) -> BenchmarkSchemaWithResults:
    """Run evaluation for the given benchmark config and schema."""

    match args.target.name:
        case "idb":
            assert isinstance(args.target, IdbTarget)
            async with Run(StartRPCServerTask)(
                args.target.ida_dir, str(args.target.idb)
            ) as rpc_handle:
                service = await rpc_handle
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
) -> None:
    """Acquire evidence for the selected harness and run the grading loop."""

    # parse rubric
    schema = cast(BenchmarkSchema, await Run(ParseBenchmarkTask)(BenchmarkSchema, args.rubric))

    if args.verbose:
        print(f"Rubric: {schema.name} v{schema.version}")
        print(f"Rubrics: {len(schema.rubrics)} entries")
        print()

    # run evaluation
    results = await _run_eval(args, schema)


def main() -> None:
    args = get_config()
    schema, output = asyncio.run(_run_benchmark(args))

    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(output, indent=2), encoding="utf-8")

    if args.json:
        print(json.dumps(output, indent=2))
        return

    print(f"=== {schema.name} v{schema.version} ===")
    print(f"Overall score: {output['score']:.1%} ({output['passed']}/{output['total']} passed)")
    print(f"Weighted score: {output['weighted_score']:.1%}")
    print()
    for r in output["entries"]:
        status = "✓" if r["overall_passed"] else "✗"
        print(f"  [{status}] {r['rubric_name']}")

        if args.verbose:
            for criterion in r["results"]:
                c_status = "✓" if criterion["passed"] else "✗"
                print(f"      [{c_status}] {criterion['description']}")
                print(f"             {criterion['reasoning']}")
            print()


if __name__ == "__main__":
    main()
