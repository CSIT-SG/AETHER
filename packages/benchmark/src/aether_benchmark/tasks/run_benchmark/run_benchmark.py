import os
from pathlib import Path
from typing import Any, cast

from aether_benchmark.tasks.evaluate import (
    ChatbotEvidenceAdapter,
    EvaluateTask,
    IDAEvidenceAdapter,
)
from aether_benchmark.tasks.evaluate.models import EvaluateRubric
from aether_benchmark.tasks.parse_benchmark.models import RubricsSchema
from aether_benchmark.tasks.start_rpc_server import StartRPCServerTask
from aether_benchmark.utils.task import Run, Task

from .models import BenchmarkInput, BenchmarkResult


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


class RunBenchmarkTask(Task[[RubricsSchema, BenchmarkInput, dict[str, str]], BenchmarkResult]):
    async def start(
        self,
        schema: RubricsSchema,
        inputs: BenchmarkInput,
        config: dict[str, str],
        *,
        verbose: bool = False,
    ) -> BenchmarkResult:
        if inputs["kind"] == "ida":
            idb = inputs.get("idb")
            if idb is None:
                raise ValueError("ida harness requires --idb <path>")
            ida_dir = inputs.get("ida_dir") or Path(os.environ["IDADIR"])
            async with Run(StartRPCServerTask)(ida_dir, str(idb)) as rpc_handle:
                service = await rpc_handle
                return await self._evaluate(
                    schema, service, IDAEvidenceAdapter(), config, verbose=verbose
                )
        # chatbot
        doc = inputs.get("doc")
        if doc is None:
            raise ValueError("chatbot harness requires --doc <transcript.md>")
        evidence = doc.read_text(encoding="utf-8")
        return await self._evaluate(
            schema, evidence, ChatbotEvidenceAdapter(), config, verbose=verbose
        )

    async def _evaluate(
        self,
        schema: RubricsSchema,
        evidence: Any,
        adapter: Any,
        config: dict[str, str],
        *,
        verbose: bool = False,
    ) -> BenchmarkResult:
        """Run the grading agent over every rubric entry, collecting results  + weights."""
        entry_results: list[dict[str, Any]] = []
        weights: list[float] = []

        for entry in schema.rubrics:
            if verbose:
                print(f"  Evaluating {entry.name}...", end="", flush=True)

            result = await Run(EvaluateTask)(
                cast(EvaluateRubric, entry.model_dump()), evidence, config, adapter
            )

            entry_results.append(result)
            weights.append(entry.weight)

            if verbose:
                status = "PASS" if result["overall_passed"] else "FAIL"
                print(f" {status}")

        if verbose:
            print()

        aggregate = _aggregate(entry_results, weights)

        output = BenchmarkResult(
            benchmark_name=schema.name,
            benchmark_version=schema.version or "",
            entries=entry_results,
            score=aggregate["score"],
            passed=aggregate["passed"],
            total=aggregate["total"],
            weighted_score=aggregate["weighted_score"],
        )
        if "total_weight" in aggregate:
            output["total_weight"] = aggregate["total_weight"]
        return output

    async def cancel(self) -> None:
        return None
