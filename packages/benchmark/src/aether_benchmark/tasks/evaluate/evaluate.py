from __future__ import annotations

import asyncio
import re
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
from aether_utils.get_content import get_content
from agents import (
    Agent,
    OpenAIChatCompletionsModel,
    Runner,
)
from openai import AsyncOpenAI
from pydantic import BaseModel

from aether_benchmark.utils.task import Task


class CriterionResult(BaseModel):
    """Result of evaluating a single criterion."""

    description: str
    passed: bool
    reasoning: str


_HERE = Path(__file__).resolve().parent.parent.parent
_SYSTEM_PROMPT = get_content(_HERE, "evaluate_prompt.md")

_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]+")


class EvaluateTask(Task[[dict[str, Any], Any, dict[str, Any]], dict[str, Any]]):  # type: ignore[misc]
    """Evaluate a single rubric entry against IDB state.

    Gives the LLM direct access to the forwarded RPC functions.
    """

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
        addresses = _extract_addresses(rubric.get("description", ""))

        criteria = rubric.get("criteria", [])
        tasks = [
            _evaluate_criterion(text, addresses, rubric_name, model, service) for text in criteria
        ]
        results = await asyncio.gather(*tasks)
        overall = all(r["passed"] for r in results)

        return {
            "rubric_name": rubric_name,
            "addresses": addresses,
            "results": list(results),
            "overall_passed": overall,
        }

    async def cancel(self) -> None:
        pass


def _extract_addresses(description: str) -> list[str]:
    """Extract all hex addresses from a rubric description (e.g. ``0x4010A0``)."""
    return _ADDRESS_RE.findall(description)


async def _evaluate_criterion(
    text: str,
    addresses: list[str],
    rubric_name: str,
    model: OpenAIChatCompletionsModel,
    service: Any,
) -> dict[str, Any]:
    agent = Agent(
        name="CriterionEvaluator",
        instructions=_SYSTEM_PROMPT,
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

    prompt = _build_prompt(text, addresses, rubric_name)
    result = await Runner.run(
        agent, prompt, context=SubagentToolDependencies(service), max_turns=20
    )

    try:
        cr = await force_structured_output(agent, CriterionResult, result)
        return {"description": cr.description, "passed": cr.passed, "reasoning": cr.reasoning}
    except Exception as e:
        return {"description": text, "passed": False, "reasoning": f"Evaluation failed: {e}"}


def _build_prompt(text: str, addresses: list[str], rubric_name: str) -> str:
    """Prompt with the criterion and target addresses."""
    addrs = ", ".join(addresses) if addresses else "(no specific addresses)"
    return f"""# Rubric: {rubric_name}
## Criterion

{text}

## Target Addresses

{addrs}

Use the available tools to inspect the target function(s) and gather
the evidence you need to evaluate this criterion.
"""
