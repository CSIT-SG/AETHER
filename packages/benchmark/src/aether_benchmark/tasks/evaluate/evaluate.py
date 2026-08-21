from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from aether_backend.forwarded_rpc import (
    get_data_at_address,
    get_function_pseudocode,
    get_functions_called_recursively,
    get_local_variables,
)
from aether_backend.utils.force_structured_output import force_structured_output
from aether_backend.utils.subagent import (
    SubagentToolDependencies,
    build_subagent_tool,
)
from agents import (
    Agent,
    OpenAIChatCompletionsModel,
    Runner,
)
from openai import AsyncOpenAI

from aether_benchmark.tasks.evaluate.models import CriterionResult
from aether_benchmark.utils.task import Task
from aether_utils.get_content import get_content

class EvaluateTask(Task[[dict[str, Any], Any, dict[str, Any]], dict[str, Any]]):  # type: ignore[misc]
    """Evaluate a single rubric entry against IDB state.

    Gives the LLM direct access to the forwarded RPC functions, so it can
    inspect function state on demand rather than relying on pre-parsed data.
    """

    _SYSTEM_PROMPT = get_content(Path(__file__).parent, "evaluate_prompt.md")

    async def start(
        self,
        rubric: dict[str, Any],
        service: Any,
        config: dict[str, Any],
    ) -> dict[str, Any]:
        api_key = config["api_key"]
        base_url = config.get("base_url", "https://openrouter.ai/api/v1")
        model_name = config.get("model", "qwen/qwen3.7-flash")

        client = AsyncOpenAI(api_key=api_key, base_url=base_url)
        model = OpenAIChatCompletionsModel(model=model_name, openai_client=client)

        rubric_name = rubric.get("name", "")
        description = rubric.get("description", "")

        criteria = rubric.get("criteria", [])
        tasks = [
            self._evaluate_criterion(text, description, rubric_name, model, service)
            for text in criteria
        ]
        results = await asyncio.gather(*tasks)
        overall = all(r["passed"] for r in results)

        return {
            "rubric_name": rubric_name,
            "results": list(results),
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
        service: Any,
    ) -> CriterionResult:
        agent = Agent(
            name="CriterionEvaluator",
            instructions=self._SYSTEM_PROMPT,
            model=model,
            tools=list(
                map(
                    build_subagent_tool,
                    [
                        get_data_at_address,
                        get_function_pseudocode,
                        get_local_variables,
                        get_functions_called_recursively,
                    ],
                )
            ),
        )

        prompt = self._build_prompt(text, description, rubric_name)
        result = await Runner.run(agent, prompt, context=SubagentToolDependencies(service), max_turns=20)

        try:
            cr = await force_structured_output(agent, CriterionResult, result)
            return cr
        except Exception as e:
            return {"passed": False, "reasoning": f"Evaluation failed: {e}"}

    @staticmethod
    def _build_prompt(text: str, description: str, rubric_name: str) -> str:
        """Prompt with the criterion and rubric description."""
        return f"""# Rubric: {rubric_name}
## Description

{description}

## Criterion

{text}

Use the available tools to inspect the target function(s) and gather
the evidence you need to evaluate this criterion.
"""
