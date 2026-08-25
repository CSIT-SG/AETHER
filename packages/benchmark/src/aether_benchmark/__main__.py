"""
Usage:
    python -m aether_benchmark --kind ida --idb <path> --rubric <path> --api-key <key> --ida-dir <dir>
    python -m aether_benchmark --kind chatbot --doc <transcript.md> --rubric <path> --api-key <key>
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
from typing import Any

from aether_benchmark.tasks.evaluate import ChatbotEvidenceAdapter, IDAEvidenceAdapter
from aether_benchmark.tasks.parse_benchmark.models import RubricsSchema
from aether_benchmark.utils.task import Run

from .tasks import EvaluateTask, ParseBenchmarkTask, StartRPCServerTask


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AETHER Benchmark — evaluate annotation quality against rubric."
    )
    parser.add_argument(
        "--kind",
        choices=["ida", "chatbot"],
        default="ida",
        help="'ida' grades a pre-annotated IDB, 'chatbot' grades a transcript of chatbot conversation",
    )
    parser.add_argument(
        "--idb", type=Path, help="Path to the IDB/i64/binary to evaluate (kind=ida)"
    )
    parser.add_argument(
        "--doc",
        type=Path,
        help="Path to the chatbot conversation transcript markdown (kind=chatbot)",
    )
    parser.add_argument("--rubric", required=True, type=Path, help="Path to the rubric YAML file")
    parser.add_argument(
        "--api-key",
        default=os.environ["OPENROUTER_API_KEY"],
        help="OpenRouter/OpenAI API key (default: OPENROUTER_API_KEY env)",
    )
    parser.add_argument(
        "--model", default="openai/gpt-5-mini", help="Model slug (default: openai/gpt-5-mini)"
    )
    parser.add_argument("--base-url", default="https://openrouter.ai/api/v1", help="API base URL")
    parser.add_argument(
        "--ida-dir",
        type=Path,
        help="IDA Pro installation directory (default: IDADIR env; only used for kind=ida)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show detailed per-entry results"
    )
    parser.add_argument("--json", action="store_true", help="Output raw JSON only")
    return parser


def _validate_args(args: argparse.Namespace) -> None:
    """Ensure the arguments match the selected harness (``--kind``)."""
    if args.kind == "ida" and args.idb is None:
        raise SystemExit("--kind ida requires --idb <path>")
    if args.kind == "chatbot" and args.doc is None:
        raise SystemExit("--kind chatbot requires --doc <transcript.md>")


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
    for result, w in zip(results, weights, strict=True):
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


async def _evaluate_entries(
    benchmark: RubricsSchema,
    evidence: Any,
    adapter: Any,
    config: dict[str, str],
    verbose: bool,
) -> tuple[list[dict[str, Any]], list[float]]:
    """Run the grading agent over every rubric entry, collecting results + weights."""
    entry_results: list[dict[str, Any]] = []
    weights: list[float] = []

    for entry in benchmark.rubrics:
        if verbose:
            print(f"  Evaluating {entry.name}...", end="", flush=True)

        result = await Run(EvaluateTask)(entry.model_dump(), evidence, config, adapter)

        entry_results.append(result)
        weights.append(entry.weight)

        if verbose:
            status = "PASS" if result["overall_passed"] else "FAIL"
            print(f" {status}")

    if verbose:
        print()

    return entry_results, weights


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
    # start rpc server if idb file is taken if not just use the transcript as evidence
    if args.kind == "ida":
        ida_dir = args.ida_dir or Path(os.environ["IDADIR"])
        async with Run(StartRPCServerTask)(ida_dir, str(args.idb)) as rpc_handle:
            service = await rpc_handle
            entry_results, weights = await _evaluate_entries(
                benchmark, service, IDAEvidenceAdapter(), config, args.verbose
            )
    else:
        # chatbot evaluation, read the transcript and pass it to the adapter
        evidence = args.doc.read_text(encoding="utf-8")
        entry_results, weights = await _evaluate_entries(
            benchmark, evidence, ChatbotEvidenceAdapter(), config, args.verbose
        )

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
    print(
        f"Overall score: {aggregate['score']:.1%} ({aggregate['passed']}/{aggregate['total']} passed)"
    )
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
    _validate_args(args)
    asyncio.run(_run_benchmark(args))


if __name__ == "__main__":
    main()
