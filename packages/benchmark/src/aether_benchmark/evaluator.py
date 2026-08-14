"""LLM-based evaluation agent for rubric scoring.

Uses the OpenAI Agents SDK directly (no AETHER wrappers) to evaluate each
rubric entry against data extracted from the IDB.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

from agents import (
    Agent,
    ModelSettings,
    OpenAIChatCompletionsModel,
    Runner,
    RunResult,
    function_tool,
)
from agents.agent import StopAtTools
from openai import AsyncOpenAI

from .idb_extractor import FunctionState
from .models import CriterionResult, RubricEntry, RubricEvalResult

_HERE = Path(__file__).resolve().parent

# Resolve the content directory for both source layout (packages/benchmark/content)
# and wheel layout (aether_benchmark/content packaged via force-include).
_CONTENT_CANDIDATES = [
    _HERE.parent.parent / "content",  # source checkout
    _HERE / "content",  # installed wheel
]
_CONTENT_DIR = next((p for p in _CONTENT_CANDIDATES if (p / "evaluate_prompt.md").is_file()), None)
if _CONTENT_DIR is None:
    raise FileNotFoundError(
        "evaluate_prompt.md not found. Tried: "
        + ", ".join(str(p / "evaluate_prompt.md") for p in _CONTENT_CANDIDATES)
    )

SYSTEM_PROMPT = (_CONTENT_DIR / "evaluate_prompt.md").read_text(encoding="utf-8")

_MAX_SUBMIT_RETRIES = 3


def _build_prompt(entry: RubricEntry, state: FunctionState) -> str:
    """Build the user message for the LLM with rubric criteria + IDB state."""
    criteria_block = "\n".join(f"  [{c.id}] {c.description}" for c in entry.criteria)

    return f"""# Rubric Entry: {entry.id}

{entry.description}

## Criteria to Evaluate

{criteria_block}

## Extracted Function State

**Function Name:** {state.function_name}
**Address:** {state.address}
**Was Renamed:** {"Yes" if state.is_renamed else "No — still auto-generated"}
**Has Header Comment:** {"Yes" if state.has_header_comment else "No"}

**Local Variables:**
{chr(10).join(f"  - {v['name']}: {v['type']}" + (" (argument)" if v.get("is_arg") else "") for v in state.local_variables) if state.local_variables else "  (none or unavailable)"}

**Inline Comments Found:** {len(state.inline_comments)}
{"  - " + chr(10).join(state.inline_comments[:10]) if state.inline_comments else "  (none)"}

**Called Functions:**
{chr(10).join(f"  - {n}" for n in state.callee_names) if state.callee_names else "  (none or unavailable)"}

**Pseudocode:**
{state.pseudocode[:4000] if state.pseudocode else "  (unavailable)"}

---

Evaluate each criterion listed above. Call `submit_output` with your findings.
"""


async def _force_structured_output(
    agent: Agent,
    output_type: type[RubricEvalResult],
    result: RunResult,
) -> RubricEvalResult:
    """Force the agent to return structured output via a tool call.

    Works around gateway providers that don't support native structured output
    (e.g. Qwen via OpenRouter).
    """
    captured: RubricEvalResult | None = cast(RubricEvalResult | None, None)

    async def _submit_output(args: RubricEvalResult) -> None:  # type: ignore[valid-type]
        nonlocal captured
        captured = args

    _submit_output.__annotations__["args"] = output_type
    submit_tool = function_tool(_submit_output, name_override="submit_output")

    submission_agent = agent.clone(
        tools=[*agent.tools, submit_tool],
        tool_use_behavior=StopAtTools(stop_at_tool_names=[submit_tool.name]),
        model_settings=ModelSettings(tool_choice="required"),
    )

    retries = _MAX_SUBMIT_RETRIES
    while captured is None and retries > 0:
        result = await Runner.run(
            submission_agent,
            input=result.to_input_list()
            + [
                {
                    "role": "user",
                    "content": f"Call {submit_tool.name} with your findings to submit them.",
                }
            ],
            max_turns=10,
        )
        retries -= 1

    if captured is None:
        raise RuntimeError(
            f"Model did not call {submit_tool.name} after {_MAX_SUBMIT_RETRIES} retries."
        )
    return captured


def create_model(
    *,
    api_key: str,
    base_url: str = "https://openrouter.ai/api/v1",
    model_name: str = "qwen/qwen3.7-flash",
) -> OpenAIChatCompletionsModel:
    """Create an OpenAI-compatible model for the benchmark's evaluation agent.

    Parameters
    ----------
    api_key:
        API key for the provider (e.g. OpenRouter key).
    base_url:
        Base URL of the OpenAI-compatible API.
    model_name:
        Model identifier as recognised by the provider.

    Returns
    -------
    OpenAIChatCompletionsModel
        Ready-to-use model for the Agents SDK.
    """
    client = AsyncOpenAI(api_key=api_key, base_url=base_url)
    return OpenAIChatCompletionsModel(model=model_name, openai_client=client)


async def evaluate_entry(
    entry: RubricEntry,
    state: FunctionState,
    model: OpenAIChatCompletionsModel,
) -> RubricEvalResult:
    """Evaluate a single rubric entry against extracted IDB state.

    Parameters
    ----------
    entry:
        The rubric entry describing what to evaluate.
    state:
        Extracted function state from the IDB.
    model:
        The LLM model to use for evaluation.

    Returns
    -------
    RubricEvalResult
        Structured evaluation with per-criterion results.
    """
    prompt = _build_prompt(entry, state)

    agent = Agent(
        name="RubricEvaluator",
        instructions=SYSTEM_PROMPT,
        model=model,
    )

    # First pass: let the model produce its answer
    result = await Runner.run(agent, prompt, max_turns=10)

    # Force structured output via tool call
    eval_result = await _force_structured_output(agent, RubricEvalResult, result)

    # Validate that all criteria got a result
    entry_cids = {c.id for c in entry.criteria}
    result_cids = {r.criterion_id for r in eval_result.criterion_results}

    missing = entry_cids - result_cids
    if missing:
        # Fill in missing criteria as failed
        extra = [
            CriterionResult(
                criterion_id=cid,
                passed=False,
                reasoning="Not addressed by evaluator.",
            )
            for cid in missing
        ]
        eval_result.criterion_results.extend(extra)

    extra = result_cids - entry_cids
    if extra:
        # Prune spurious criteria the model invented
        eval_result.criterion_results = [
            r for r in eval_result.criterion_results if r.criterion_id in entry_cids
        ]

    return eval_result
