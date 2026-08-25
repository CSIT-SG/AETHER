from __future__ import annotations

import asyncio
from typing import Any

from aether_backend.utils.force_structured_output import force_structured_output
from agents import (
    Agent,
    OpenAIChatCompletionsModel,
    RunConfig,
    Runner,
)
from openai import AsyncOpenAI

from aether_benchmark.tasks.evaluate.adapter import EvidenceAdapter
from aether_benchmark.tasks.evaluate.models import (
    CriterionResult,
    EvaluateConfig,
    EvaluateRubric,
)
from aether_benchmark.utils.task import Task


class EvaluateTask[TConfig: EvaluateConfig](
    Task[[EvaluateRubric, Any, TConfig, EvidenceAdapter], dict[str, Any]]
):
    """Evaluate a single rubric entry against supplied information/evidence.
    """

    async def start(
        self,
        rubric: EvaluateRubric,
        evidence: Any,
        config: TConfig,
        adapter: EvidenceAdapter,
    ) -> dict[str, Any]:
        api_key = config["api_key"]
        base_url = config.get("base_url", "https://openrouter.ai/api/v1")
        model_name = config.get("model", "openai/gpt-5-mini")

        client = AsyncOpenAI(api_key=api_key, base_url=base_url)
        model = OpenAIChatCompletionsModel(model=model_name, openai_client=client)

        rubric_name = rubric.get("name", "")
        description = rubric.get("description", "")

        criteria = rubric.get("criteria") or []
        tasks = [
            self._evaluate_criterion(text, description, rubric_name, model, evidence, adapter)
            for text in criteria
        ]
        results = await asyncio.gather(*tasks)
        overall = all(r["passed"] for r in results)

        return {
            "rubric_name": rubric_name,
            "results": [
                {**r, "description": text} for r, text in zip(results, criteria, strict=True)
            ],
            "overall_passed": overall,
        }

    async def cancel(self) -> None:
        pass

    async def _evaluate_criterion(
        self,
        text: str,
        description: str,
        rubric_name: str,
        model: OpenAIChatCompletionsModel,
        evidence: Any,
        adapter: EvidenceAdapter,
    ) -> CriterionResult:
        agent = Agent(
            name="CriterionEvaluator",
            instructions=adapter.system_prompt,
            model=model,
            tools=adapter.build_tools(),
        )

        prompt = adapter.build_prompt(evidence, text, description, rubric_name)
        result = await Runner.run(
            agent,
            prompt,
            context=adapter.run_context(evidence),
            max_turns=20,
            run_config=RunConfig(tracing_disabled=True),
        )

        try:
            cr = await force_structured_output(agent, CriterionResult, result)
            return cr
        except Exception as e:
            return {"passed": False, "reasoning": f"Evaluation failed: {e}"}
