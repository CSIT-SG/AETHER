"""
Usage:
    python -m aether_benchmark --idb <path> --rubric <path> --api-key <key> --ida-dir <dir>
    python -m aether_benchmark --doc <transcript.md> --rubric <path> --api-key <key>
"""

import asyncio
import json
import logging
from typing import cast

from aether_utils.logger import get_logger

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
    if args.verbose:
        print(f"Rubric: {schema.name} v{schema.version}")
        print(f"Rubrics: {len(schema.rubrics)} entries")
        print()
    results = await _run_eval(args, schema)
    return results


def _aggregate(
    rubric_results: list[bool],
    weights: list[float],
) -> dict[str, float | int]:
    """Compute overall weighted score."""
    total = len(rubric_results)
    passed = sum(rubric_results)
    total_weight = sum(weights)
    weighted_score = (
        sum(w for r, w in zip(rubric_results, weights, strict=True) if r) / total_weight
        if total_weight > 0
        else 0.0
    )
    score = passed / total if total else 0.0
    return {"score": score, "passed": passed, "total": total, "weighted_score": weighted_score}


def main() -> None:
    args = get_config()
    results = asyncio.run(_run_benchmark(args))

    output = results.model_dump()
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(output, indent=2), encoding="utf-8")
    if args.json_output:
        print(json.dumps(output, indent=2))
        return

    rubric_passed_flags = [
        all(c.result["success"] and c.result["data"]["passed"] for c in rubric.criteria)
        for rubric in results.rubrics
    ]
    weights = [rubric.weight for rubric in results.rubrics]
    agg = _aggregate(rubric_passed_flags, weights)

    print(f"=== {results.name} v{results.version} ===")
    for rubric, rubric_passed in zip(results.rubrics, rubric_passed_flags, strict=True):
        status = "✓" if rubric_passed else "✗"
        print(f"  [{status}] {rubric.name}")
        if args.verbose:
            for c in rubric.criteria:
                if c.result["success"]:
                    c_status = "✓" if c.result["data"]["passed"] else "✗"
                    reasoning = c.result["data"]["reasoning"]
                else:
                    c_status = "!"
                    reasoning = f"Agent run failed: {c.result['error']}"
                print(f"      [{c_status}] {c.criterion}")
                print(f"             {reasoning}")
            print()

    print(f"Overall score: {agg['score']:.1%} ({agg['passed']}/{agg['total']} passed)")
    print(f"Weighted score: {agg['weighted_score']:.1%}")


if __name__ == "__main__":
    main()
