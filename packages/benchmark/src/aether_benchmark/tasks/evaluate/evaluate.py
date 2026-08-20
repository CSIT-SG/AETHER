from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import jinja2
from pydantic import BaseModel

from openai import AsyncOpenAI

from agents import (
    Agent,
    OpenAIChatCompletionsModel,
    Runner,
)

from aether_backend.utils.force_structured_output import force_structured_output
from aether_utils.get_content import get_content

from aether_benchmark.utils.task import Task



class CriterionResult(BaseModel):
    """Result of evaluating a single criterion."""

    description: str
    passed: bool
    reasoning: str


_HERE = Path(__file__).resolve().parent.parent.parent
_SYSTEM_PROMPT = get_content(_HERE, "evaluate_prompt.md")

_TEMPLATE_SRC = get_content(_HERE, "evaluate_message.md.j2")
_PROMPT_TEMPLATE = jinja2.Template(_TEMPLATE_SRC)


class EvaluateTask(Task[[dict[str, Any], Any, dict[str, Any]], dict[str, Any]]):  # type: ignore[misc]
    """Evaluate a single rubric entry against IDB state.

    Pre-fetches function state via RPC, then evaluates each criterion
    with one LLM call per criterion — no agent tool calls.
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


        address = rubric.get("function_address", "")
        state = await _fetch_state(service, address)

        
        criteria = rubric.get("criteria", [])
        tasks = [
            _evaluate_criterion(text, state, rubric["id"], model)
            for text in criteria
        ]
        results = await asyncio.gather(*tasks)
        overall = all(r["passed"] for r in results)

        return {
            "rubric_id": rubric.get("id", ""),
            "results": list(results),
            "overall_passed": overall,
        }

    async def cancel(self) -> None:
        pass


async def _fetch_state(service: Any, address: str) -> dict[str, Any]:
    """Pre-fetch all function data we need for evaluation."""
    state: dict[str, Any] = {
        "address": address,
        "function_name": "(unknown)",
        "pseudocode": "(unavailable)",
        "local_variables": [],
        "callee_names": [],
    }

    try:
        r = service.get_data_at_address(location=address)
        if r.success:
            state["function_name"] = r.result.get("name", "(unknown)")
    except Exception:
        pass

    fn_name = state["function_name"]
    if fn_name and not fn_name.startswith("(unknown)") and not fn_name.startswith("Error"):
        try:
            r = service.get_function_pseudocode(function_name=fn_name)
            if r.success:
                ps = r.result.get("pseudocode", "")
                state["pseudocode"] = ps[:6000] if ps else "(empty)"
        except Exception:
            pass

        try:
            r = service.get_local_variables(function_name=fn_name)
            if r.success:
                state["local_variables"] = r.result
        except Exception:
            pass

        try:
            r = service.get_functions_called_recursively(address=address)
            if r.success:
                tree = r.result.get("root", {})
                names = _collect_names(tree.get("children", []))
                state["callee_names"] = names
        except Exception:
            pass

    return state


def _collect_names(children: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    _walk_children(children, out)
    return out


def _walk_children(children: list[dict[str, Any]], out: list[str]) -> None:
    for child in children:
        name = child.get("function_name", "(unknown)")
        if name not in out:
            out.append(name)
        _walk_children(child.get("children", []), out)


async def _evaluate_criterion(
    text: str,
    state: dict[str, Any],
    rubric_id: str,
    model: OpenAIChatCompletionsModel,
) -> dict[str, Any]:
    """Evaluate one criterion against pre-fetched state."""
    prompt = _build_prompt(text, state, rubric_id)

    agent = Agent(
        name="CriterionEvaluator",
        instructions=_SYSTEM_PROMPT,
        model=model,
    )

    result = await Runner.run(agent, prompt, max_turns=5)

    try:
        cr = await force_structured_output(agent, CriterionResult, result)
        return {"description": cr.description, "passed": cr.passed, "reasoning": cr.reasoning}
    except Exception as e:
        return {"description": text, "passed": False, "reasoning": f"Evaluation failed: {e}"}


def _build_prompt(text: str, state: dict[str, Any], rubric_id: str) -> str:
    """Build the user prompt with full function state inline."""
    return _PROMPT_TEMPLATE.render(text=text, state=state, rubric_id=rubric_id)
