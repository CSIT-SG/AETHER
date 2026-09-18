from aether_backend.utils.effect import Program, Progress
from agents import RunResultStreaming


async def stream_tool_logs(result: RunResultStreaming) -> Program:
    """Drain a streamed agent run, yielding a `Log` per tool call and tool output.

    Consumes `result` to completion, so `result.final_output` is available once
    this returns.

    eg:
    ```python
    result = Runner.run_streamed(agent, context=deps, input=prompt)

    async for log in stream_tool_logs(result):
        yield log

    yield Return(result.final_output)
    ```
    """
    async for event in result.stream_events():
        if event.type != "run_item_stream_event":
            continue

        run_item = event.item
        if run_item.type == "tool_call_item":
            args = getattr(run_item.raw_item, "arguments", "")
            yield Progress(f"{run_item.tool_name}({args})")

        elif run_item.type == "tool_call_output_item":
            yield Progress(str(run_item.output))
