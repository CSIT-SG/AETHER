from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

from agents import (
    Agent,
    OpenAIChatCompletionsModel,
    Runner,
)
import jinja2
from openai import AsyncOpenAI
from pydantic import BaseModel

from aether_backend.forwarded_rpc import (
    get_data_at_address,
    get_function_pseudocode,
    get_functions_called_recursively,
    get_local_variables,
)
from aether_backend.utils.force_structured_output import force_structured_output
from aether_benchmark.utils.task import Task
from aether_utils.get_content import get_content


class CriterionResult(BaseModel):
    """Result of evaluating a single criterion."""

    description: str
    passed: bool
    reasoning: str


_HERE = Path(__file__).resolve().parent.parent.parent
_SYSTEM_PROMPT = get_content(_HERE, "evaluate_prompt.md")

_TEMPLATE_SRC = get_content(_HERE, "evaluate_message.jinja")
_PROMPT_TEMPLATE = jinja2.Template(_TEMPLATE_SRC)

_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]+")


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

        rubric_name = rubric.get("name", "")
        addresses = _extract_addresses(rubric.get("description", ""))
        states = await _fetch_states(service, addresses)

        criteria = rubric.get("criteria", [])
        tasks = [
            _evaluate_criterion(text, states, rubric_name, model)
            for text in criteria
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


async def _fetch_states(service: Any, addresses: list[str]) -> list[dict[str, Any]]:
    """Pre-fetch function state for each target address.

    Uses the ``forwarded_rpc`` wrappers as MCP tools.
    """
    return await asyncio.gather(*(_fetch_state(service, address) for address in addresses))


async def _fetch_state(service: Any, address: str) -> dict[str, Any]:
    """Pre-fetch all function data we need for a single address."""
    state: dict[str, Any] = {
        "address": address,
        "function_name": "(unknown)",
        "pseudocode": "(unavailable)",
        "local_variables": [],
        "call_tree": None,
    }

    try:
        r = await get_data_at_address(service, location=address)
        if r.success:
            data: Any = r.result
            state["function_name"] = data.get("name", "(unknown)")
    except Exception:
        pass

    fn_name = state["function_name"]
    if fn_name and not fn_name.startswith("(unknown)") and not fn_name.startswith("Error"):
        try:
            r = await get_function_pseudocode(service, function_name=fn_name)
            if r.success:
                data: Any = r.result
                ps = data.get("pseudocode", "")
                state["pseudocode"] = ps[:6000] if ps else "(empty)"
        except Exception:
            pass

        try:
            r = await get_local_variables(service, function_name=fn_name)
            if r.success:
                state["local_variables"] = r.result
        except Exception:
            pass

        try:
            r = await get_functions_called_recursively(service, address=address)
            if r.success:
                data: Any = r.result
                state["call_tree"] = data.get("root")
        except Exception:
            pass

    return state


async def _evaluate_criterion(
    text: str,
    states: list[dict[str, Any]],
    rubric_name: str,
    model: OpenAIChatCompletionsModel,
) -> dict[str, Any]:
    """Evaluate one criterion against pre-fetched state."""
    prompt = _build_prompt(text, states, rubric_name)

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


def _build_prompt(text: str, states: list[dict[str, Any]], rubric_name: str) -> str:
    """Build the user prompt with full function state inline."""
    return _PROMPT_TEMPLATE.render(text=text, states=states, rubric_name=rubric_name)
