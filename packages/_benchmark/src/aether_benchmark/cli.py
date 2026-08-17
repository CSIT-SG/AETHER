"""CLI entry point for the AETHER benchmark tool.

Usage
-----
    aether-benchmark --idb <path.i64> --rubric <path.yaml> [options]
    python -m aether_benchmark --idb <path.i64> --rubric <path.yaml>
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections import defaultdict
from dataclasses import fields
from pathlib import Path
from typing import Any

import yaml
from agents import set_tracing_disabled

from .evaluator import create_model, evaluate_entry
from .idb_extractor import FunctionState, extract_function_state
from .models import (
    BenchmarkDef,
    BenchmarkResult,
    RubricEntry,
    RubricEvalResult,
    RubricScore,
)


def load_rubric(path: str | Path) -> BenchmarkDef:
    """Load and validate a rubric YAML file."""
    path = Path(path)
    if not path.is_file():
        print(f"Error: rubric file not found: {path}", file=sys.stderr)
        sys.exit(1)

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        print(f"Error: invalid YAML in rubric: {e}", file=sys.stderr)
        sys.exit(1)

    # Support both `{benchmark: {...}, rubrics: [...]}` and a flat structure
    # where the benchmark metadata and rubrics live at the top level.
    if isinstance(raw, dict) and "benchmark" in raw and isinstance(raw["benchmark"], dict):
        wrapped = raw["benchmark"]
        if "rubrics" not in wrapped and "rubrics" in raw:
            wrapped["rubrics"] = raw["rubrics"]
        raw = wrapped

    try:
        return BenchmarkDef.model_validate(raw)
    except Exception as e:
        print(f"Error: rubric validation failed: {e}", file=sys.stderr)
        sys.exit(1)


def extract_state_from_idb(
    idb_path: str,
    entries: list[RubricEntry],
    ida_dir: str | None,
    verbose: bool,
) -> dict[str, Any]:
    """Extract function state for all rubric entries from an IDB.

    Returns a dict mapping rubric entry ID -> extracted state dict.
    Falls back to placeholder state if idapro is not available.
    """
    states: dict[str, Any] = {}
    for entry in entries:
        if verbose:
            print(
                f"  Extracting state for {entry.id} ({entry.function_address})...",
                file=sys.stderr,
            )
        state = extract_function_state(idb_path, entry.function_address, ida_dir)
        states[entry.id] = state
    return states


def compute_scores(
    results: list[tuple[RubricEntry, RubricEvalResult]],
) -> BenchmarkResult:
    """Aggregate individual rubric evaluations into final scores."""
    per_entry: list[RubricScore] = []
    total_weight = 0.0
    weighted_sum = 0.0
    passed_count = 0

    # Per-tier aggregates
    tier_scores: dict[str, list[float]] = defaultdict(list)
    # Per-feature aggregates
    feature_scores: dict[str, list[float]] = defaultdict(list)

    for entry, eval_result in results:
        n_criteria = len(entry.criteria)
        n_passed = sum(1 for r in eval_result.criterion_results if r.passed)
        raw = n_passed / n_criteria if n_criteria > 0 else 0.0

        score = RubricScore(
            rubric_id=entry.id,
            raw_score=raw,
            weighted_score=raw * entry.weight,
            passed=eval_result.passed,
            detail=eval_result,
        )
        per_entry.append(score)

        total_weight += entry.weight
        weighted_sum += raw * entry.weight
        if eval_result.passed:
            passed_count += 1

        tier_scores[entry.difficulty.value].append(raw)
        feature_scores[entry.feature.value].append(raw)

    overall = (weighted_sum / total_weight * 100.0) if total_weight > 0 else 0.0

    tier_breakdown = {
        tier: (sum(scores) / len(scores) * 100.0) for tier, scores in tier_scores.items()
    }
    feature_matrix = {
        feat: (sum(scores) / len(scores) * 100.0) for feat, scores in feature_scores.items()
    }

    return BenchmarkResult(
        benchmark_name="",
        version="",
        overall_score=round(overall, 2),
        tier_breakdown={k: round(v, 2) for k, v in tier_breakdown.items()},
        feature_matrix={k: round(v, 2) for k, v in feature_matrix.items()},
        per_entry=per_entry,
        total_entries=len(results),
        passed_entries=passed_count,
    )


def print_report(result: BenchmarkResult, verbose: bool) -> None:
    """Print a human-readable report to stdout."""
    print("=" * 60)
    print("  AETHER Benchmark Results")
    print("=" * 60)
    print(f"\n  Overall Score:  {result.overall_score:.1f}%")
    print(f"  Passed:         {result.passed_entries}/{result.total_entries} entries")
    print()

    if result.tier_breakdown:
        print("  ── Difficulty Breakdown ──")
        for tier in ("easy", "medium", "hard"):
            if tier in result.tier_breakdown:
                print(f"    {tier.title():8s}:  {result.tier_breakdown[tier]:.1f}%")
        print()

    if result.feature_matrix:
        print("  ── Feature Breakdown ──")
        for feat, score in sorted(result.feature_matrix.items()):
            print(f"    {feat:20s}:  {score:.1f}%")
        print()

    if verbose:
        print("  ── Per-Entry Details ──")
        for s in result.per_entry:
            status = "PASS" if s.passed else "FAIL"
            print(f"\n    [{status}] {s.rubric_id}  (score: {s.raw_score * 100:.0f}%)")
            print(f"    Summary: {s.detail.summary}")
            for cr in s.detail.criterion_results:
                icon = "✓" if cr.passed else "✗"
                print(f"      {icon} [{cr.criterion_id}] {cr.reasoning}")
        print()

    print("=" * 60)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aether-benchmark",
        description="Evaluate AETHER tool outputs against a rubric.",
    )

    # Input sources (one required)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--idb",
        help="Path to an .i64/.idb/binary file processed by AETHER.",
    )
    input_group.add_argument(
        "--state-json",
        help="Path to a JSON file with pre-extracted function state (skip IDB).",
    )

    parser.add_argument(
        "--rubric",
        required=True,
        help="Path to the rubric YAML file.",
    )
    parser.add_argument(
        "--api-key",
        help="OpenRouter / OpenAI API key. Falls back to OPENROUTER_API_KEY env var.",
    )
    parser.add_argument(
        "--base-url",
        default="https://openrouter.ai/api/v1",
        help="OpenAI-compatible API base URL (default: OpenRouter).",
    )
    parser.add_argument(
        "--model",
        default="qwen/qwen3.7-flash",
        help="Model identifier (default: qwen/qwen3.7-flash).",
    )
    parser.add_argument(
        "--ida-dir",
        help="Path to the IDA Pro installation directory (needed for --idb).",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print detailed per-entry evaluation results.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON only.",
    )
    return parser


async def _run_evaluation(
    benchmark: BenchmarkDef,
    states: dict[str, FunctionState],
    model: Any,
    verbose: bool,
) -> BenchmarkResult:
    """Evaluate every rubric entry against its extracted state."""
    results: list[tuple[RubricEntry, RubricEvalResult]] = []
    total = len(benchmark.rubrics)

    for idx, entry in enumerate(benchmark.rubrics, 1):
        state = states.get(entry.id)
        if state is None:
            print(
                f"Warning: no state extracted for {entry.id}, skipping.",
                file=sys.stderr,
            )
            continue

        if state.error:
            print(
                f"Warning: error extracting state for {entry.id}: {state.error}, skipping.",
                file=sys.stderr,
            )
            continue

        if verbose:
            print(f"  Evaluating [{idx}/{total}] {entry.id}...", file=sys.stderr)

        eval_result = await evaluate_entry(entry, state, model)

        results.append((entry, eval_result))

        if verbose:
            status = "PASS" if eval_result.passed else "FAIL"
            print(f"    → {status}", file=sys.stderr)

    result = compute_scores(results)
    result.benchmark_name = benchmark.name
    result.version = benchmark.version
    return result


def main(argv: list[str] | None = None) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    # ── API key resolution ────────────────────────────────────────────────
    api_key = args.api_key or _env_key()
    if not api_key:
        print(
            "Error: API key required. Provide --api-key or set OPENROUTER_API_KEY env var.",
            file=sys.stderr,
        )
        sys.exit(1)

    # ── Load rubric ──────────────────────────────────────────────────────
    if args.verbose:
        print(f"Loading rubric from {args.rubric}...", file=sys.stderr)
    benchmark = load_rubric(args.rubric)

    # ── Extract IDB state ─────────────────────────────────────────────────
    if args.idb:
        if args.verbose:
            print(f"Extracting data from {args.idb}...", file=sys.stderr)
        states = extract_state_from_idb(args.idb, benchmark.rubrics, args.ida_dir, args.verbose)
    elif args.state_json:
        if args.verbose:
            print(f"Loading pre-extracted state from {args.state_json}...", file=sys.stderr)
        states = _load_state_json(args.state_json)
    else:
        states = {}

    # ── Evaluate ──────────────────────────────────────────────────────────
    if args.verbose:
        print(f"Creating model ({args.model})...", file=sys.stderr)

    set_tracing_disabled(True)

    model = create_model(
        api_key=api_key,
        base_url=args.base_url,
        model_name=args.model,
    )

    result = asyncio.run(_run_evaluation(benchmark, states, model, args.verbose))

    # ── Output ────────────────────────────────────────────────────────────
    if args.json:
        print(result.model_dump_json(indent=2))
    else:
        print_report(result, args.verbose)


def _load_state_json(path: str) -> dict[str, FunctionState]:
    """Load pre-extracted function state from a JSON file."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    states: dict[str, FunctionState] = {}
    for key, data in raw.items():
        # Handle inline_comments format: list of [addr, text] pairs or plain text
        inline = data.get("inline_comments", [])
        if inline and isinstance(inline[0], list):
            inline = [entry[1] if isinstance(entry, list) else entry for entry in inline]

        # Reconstruct dataclass from dict
        field_names = {f.name for f in fields(FunctionState)}
        filtered = {k: v for k, v in data.items() if k in field_names and v is not None}
        states[key] = FunctionState(**filtered)
    return states


def _env_key() -> str | None:
    return os.environ.get("OPENROUTER_API_KEY") or os.environ.get("OPENAI_API_KEY")


if __name__ == "__main__":
    main()
