"""
Usage:
    python -m aether_benchmark --idb <path> --rubric <path> --api-key <key> --ida-dir <dir>
    python -m aether_benchmark --doc <transcript.md> --rubric <path> --api-key <key>
"""

import argparse
import asyncio
import json
import os
from pathlib import Path

from aether_benchmark.tasks.evaluate import (
    ChatbotEvidenceAdapter,
    IDAEvidenceAdapter,
)
from aether_benchmark.tasks.parse_benchmark.models import RubricsSchema
from aether_benchmark.tasks.run_benchmark import RunBenchmarkTask
from aether_benchmark.tasks.run_benchmark.models import BenchmarkResult
from aether_benchmark.tasks.start_rpc_server import StartRPCServerTask
from aether_benchmark.utils.task import Run

from .tasks import ParseBenchmarkTask


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AETHER Benchmark — evaluate annotation quality against rubric."
    )
    parser.add_argument("--idb", type=Path, help="Path to the IDB/i64 file")
    parser.add_argument(
        "--doc",
        type=Path,
        help="Path to the chatbot transcript markdown file",
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
        help="IDA Pro installation directory (default: IDADIR env; only used for ida harness)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show detailed per-entry results"
    )
    parser.add_argument("--json", action="store_true", help="Print the benchmark result as JSON")
    parser.add_argument(
        "--output",
        type=Path,
        help="Write the benchmark result as JSON to this file",
    )
    return parser


def _resolve(idb: Path | None, doc: Path | None) -> str:
    if idb is not None and doc is not None:
        raise SystemExit("Both --idb and --doc passed, pass only one")
    if idb is not None:
        return "ida"
    if doc is not None:
        return "chatbot"
    raise SystemExit("Provide either --idb <path> or --doc <transcript.md>")


async def _run_benchmark(
    args: argparse.Namespace,
) -> tuple[RubricsSchema, BenchmarkResult]:
    """Acquire evidence for the selected harness and run the grading loop."""
    config: dict[str, str] = {
        "api_key": args.api_key,
        "base_url": args.base_url,
        "model": args.model,
    }
    kind = _resolve(args.idb, args.doc)

    # parse rubric
    schema = await Run(ParseBenchmarkTask)(RubricsSchema, args.rubric)

    if args.verbose:
        print(f"Rubric: {schema.name} v{schema.version}")
        print(f"Rubrics: {len(schema.rubrics)} entries")
        print()

    if kind == "ida":
        assert args.idb is not None
        ida_dir = args.ida_dir or Path(os.environ["IDADIR"])
        async with Run(StartRPCServerTask)(ida_dir, str(args.idb)) as rpc_handle:
            service = await rpc_handle
            return schema, await Run(RunBenchmarkTask)(
                schema, service, IDAEvidenceAdapter(), config, verbose=args.verbose
            )  # type: ignore

    assert args.doc is not None
    evidence = args.doc.read_text(encoding="utf-8")
    return schema, await Run(RunBenchmarkTask)(
        schema, evidence, ChatbotEvidenceAdapter(), config, verbose=args.verbose
    )  # type: ignore


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
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
