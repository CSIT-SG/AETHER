from typing import cast

from agents import Agent, ModelSettings, Runner, RunResult, RunResultStreaming, function_tool
from agents.agent import StopAtTools

MAX_SUBMIT_RETRIES = 3


async def force_structured_output[T](
    agent: Agent,
    output_type: type[T],
    result: RunResult | RunResultStreaming,
    *,
    max_turns: int = 10,
) -> T:
    """Run an agent and force it to return structured output via a tool call,
    working around gateway providers that don't support structured content
    directly.

    Clones `agent` with a `submit_output` tool typed to `output_type` appended,
    and stops the run as soon as it's called. If the model finishes without
    calling it, nudges it up to `MAX_SUBMIT_RETRIES` times.

    Args:
        agent: The agent to run.
        output_type: The type of the structured output to return.
        result: An optional initial result to continue from. If not provided,
            a new run will be started.
    Returns:
        The value passed to `submit_output`.

    Raises:
        RuntimeError: if the model never calls `submit_output` after retries.
    """
    captured_output: T | None = cast(T | None, None)

    async def _submit_output(args: T) -> None:
        """Submit your final answer."""
        nonlocal captured_output
        captured_output = args
        return None

    # `output_type` is a runtime variable, not a literal type, so it can't be
    # written inline as an annotation. Patch the
    # annotation before wrapping so the SDK's runtime schema introspection
    # still sees the correct type.
    _submit_output.__annotations__["args"] = output_type
    submit_output = function_tool(_submit_output, name_override="submit_output")

    submission_agent = agent.clone(
        tools=[*agent.tools, submit_output],
        tool_use_behavior=StopAtTools(stop_at_tool_names=[submit_output.name]),
        model_settings=ModelSettings(tool_choice="required"),
    )

    retries = MAX_SUBMIT_RETRIES
    while captured_output is None and retries > 0:
        # Model ignored the tool-call requirement
        result = await Runner.run(
            submission_agent,
            input=result.to_input_list()
            + [
                {
                    "role": "user",
                    "content": f"Call {submit_output.name} with your findings to submit it properly.",
                }
            ],
            max_turns=max_turns,
        )
        retries -= 1

    if captured_output is None:
        raise RuntimeError(
            f"Model did not call {submit_output.name} after {MAX_SUBMIT_RETRIES} retries."
        )

    return captured_output
