"""
Usage:
    python -m aether_benchmark --idb <path> --rubric <path> --api-key <key> --ida-dir <dir>
    python -m aether_benchmark --doc <transcript.md> --rubric <path> --api-key <key>
"""

import asyncio
import json
import os
from pathlib import Path
from typing import cast

from aether_benchmark.tasks.evaluate import (
    ChatbotEvidenceAdapter,
    IDAEvidenceAdapter,
)
from aether_benchmark.tasks.parse_benchmark.models import RubricsSchema
from aether_benchmark.tasks.run_benchmark import RunBenchmarkTask
from aether_benchmark.tasks.run_benchmark.models import BenchmarkResult
from aether_benchmark.tasks.start_rpc_server import StartRPCServerTask
from aether_benchmark.utils.task import Run

from .cli import BenchmarkArgs, DocTarget, IdbTarget, get_args
from .tasks import ParseBenchmarkTask


async def _run_benchmark(
    args: BenchmarkArgs,
) -> tuple[RubricsSchema, BenchmarkResult]:
    """Acquire evidence for the selected harness and run the grading loop."""

    # parse rubric
    schema = cast(RubricsSchema, await Run(ParseBenchmarkTask)(RubricsSchema, args.rubric))

    if args.verbose:
        print(f"Rubric: {schema.name} v{schema.version}")
        print(f"Rubrics: {len(schema.rubrics)} entries")
        print()

    match args.target.name:
        case "idb":
            assert isinstance(args.target, IdbTarget)
            async with Run(StartRPCServerTask)(
                args.target.ida_dir, str(args.target.idb)
            ) as rpc_handle:
                service = await rpc_handle
                await Run(RunBenchmarkTask)(
                    schema, service, IDAEvidenceAdapter(), config, verbose=args.verbose
                )
        case "doc":
            assert isinstance(args.target, DocTarget)
            await Run(RunBenchmarkTask)(
                schema, evidence, ChatbotEvidenceAdapter(), config, verbose=args.verbose
            )

        case _:
            raise RuntimeError(
                f"Invariant: unknown kind {args.target.name!r} (should be 'idb' or 'doc')"
            )

    if kind == "ida":
        assert args.idb is not None
        ida_dir = args.ida_dir or Path(os.environ["IDADIR"])
        async with Run(StartRPCServerTask)(ida_dir, str(args.idb)) as rpc_handle:
            service = await rpc_handle
            return schema, await Run(RunBenchmarkTask)(
                schema, service, IDAEvidenceAdapter(), config, verbose=args.verbose
            )

    assert args.doc is not None
    evidence = args.doc.read_text(encoding="utf-8")
    return schema, await Run(RunBenchmarkTask)(
        schema, evidence, ChatbotEvidenceAdapter(), config, verbose=args.verbose
    )


def main() -> None:
    args = get_args()
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
