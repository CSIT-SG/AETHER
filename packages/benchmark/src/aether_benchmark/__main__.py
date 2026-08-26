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

from aether_benchmark.tasks.parse_benchmark.models import RubricsSchema
from aether_benchmark.tasks.run_benchmark import RunBenchmarkTask
from aether_benchmark.tasks.run_benchmark.models import BenchmarkInput
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


async def _run_benchmark(args: argparse.Namespace) -> None:

    config: dict[str, str] = {
        "api_key": args.api_key,
        "base_url": args.base_url,
        "model": args.model,
    }
    kind = _resolve(args.idb, args.doc)
    inputs: BenchmarkInput = {
        "kind": kind,
        "idb": args.idb,
        "doc": args.doc,
        "ida_dir": args.ida_dir,
    }

    # parse rubric
    schema = await Run(ParseBenchmarkTask)(RubricsSchema, args.rubric)

    if args.verbose:
        print(f"Rubric: {schema.name} v{schema.version}")
        print(f"Rubrics: {len(schema.rubrics)} entries")
        print()

    output = await Run(RunBenchmarkTask)(schema, inputs, config, verbose=args.verbose)

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


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    asyncio.run(_run_benchmark(args))


if __name__ == "__main__":
    main()
