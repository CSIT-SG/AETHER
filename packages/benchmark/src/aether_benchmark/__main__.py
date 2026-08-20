"""
Usage:
    python -m aether_benchmark --idb <path> --rubric <path> --api-key <key> --ida-dir <dir>
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
from typing import Any

from aether_benchmark.tasks.parse_benchmark.models import RubricsSchema
from aether_benchmark.utils.task import Run

from .tasks import EvaluateTask, ParseBenchmarkTask, StartRPCServerTask


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AETHER Benchmark — evaluate annotation quality against a rubric."
    )
    parser.add_argument("--idb", required=True, type=Path, help="Path to the IDB/i64/binary to evaluate")
    parser.add_argument("--rubric", required=True, type=Path, help="Path to the rubric YAML file")
    parser.add_argument("--api-key", default=os.environ["OPENROUTER_API_KEY"], help="OpenRouter/OpenAI API key (default: OPENROUTER_API_KEY env)")
    parser.add_argument("--model", default="qwen/qwen3.7-flash", help="Model slug (default: qwen/qwen3.7-flash)")
    parser.add_argument("--base-url", default="https://openrouter.ai/api/v1", help="API base URL")
    parser.add_argument("--ida-dir", default=os.environ["IDADIR"], type=Path, help="IDA Pro installation directory (default: IDADIR env)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed per-entry results")
    parser.add_argument("--json", action="store_true", help="Output raw JSON only")
    return parser


def _aggregate(
    results: list[dict[str, Any]],
    weights: list[float],
) -> dict[str, Any]:
    """Compute overall weighted score."""
    if not results:
        return {"score": 0.0, "passed": 0, "total": 0, "weighted_score": 0.0}

    total_weight = sum(weights)
    if total_weight <= 0:
        return {
            "score": 0.0,
            "passed": 0,
            "total": len(results),
            "weighted_score": 0.0,
            "message": "No positive weights",
        }

    weighted_sum = 0.0
    passed_count = 0
    for result, w in zip(results, weights):
        if result["overall_passed"]:
            passed_count += 1
            weighted_sum += w

    return {
        "score": weighted_sum / total_weight,
        "passed": passed_count,
        "total": len(results),
        "weighted_score": weighted_sum / total_weight,
        "total_weight": total_weight,
    }


async def _run_benchmark(args: argparse.Namespace) -> None:

    config: dict[str, str] = {
        "api_key": args.api_key,
        "base_url": args.base_url,
        "model": args.model,
    }

    # parse rubric
    benchmark = await Run(ParseBenchmarkTask)(RubricsSchema, args.rubric)

    if args.verbose:
        print(f"Rubric: {benchmark.name} v{benchmark.version}")
        print(f"Rubrics: {len(benchmark.rubrics)} entries")
        print()


    async with Run(StartRPCServerTask)(args.ida_dir, str(args.idb)) as rpc_handle:
        service = await rpc_handle

        entry_results: list[dict[str, Any]] = []
        weights: list[float] = []

        for entry in benchmark.rubrics:
            if args.verbose:
                print(f"  Evaluating {entry.name}...", end="", flush=True)

            result = await Run(EvaluateTask)(entry.model_dump(), service, config)

            entry_results.append(result)
            weights.append(entry.weight)

            if args.verbose:
                status = "PASS" if result["overall_passed"] else "FAIL"
                print(f" {status}")

        if args.verbose:
            print()


    aggregate = _aggregate(entry_results, weights)

    if args.json:
        output: dict[str, Any] = {
            "benchmark_name": benchmark.name,
            "benchmark_version": benchmark.version,
            "entries": entry_results,
            **aggregate,
        }
        print(json.dumps(output, indent=2))
        return

    print(f"=== {benchmark.name} v{benchmark.version} ===")
    print(f"Overall score: {aggregate['score']:.1%} ({aggregate['passed']}/{aggregate['total']} passed)")
    print(f"Weighted score: {aggregate['weighted_score']:.1%}")
    print()
    for r in entry_results:
        status = "✓" if r["overall_passed"] else "✗"
        print(f"  [{status}] {r['rubric_name']}")

        if args.verbose:
            for criterion in r["results"]:
                c_status = "✓" if criterion["passed"] else "✗"
                print(f"      [{c_status}] {criterion['description']}")
                print(f"             {criterion['reasoning']}")
            print()


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    asyncio.run(_run_benchmark(args))


if __name__ == "__main__":
    main()
