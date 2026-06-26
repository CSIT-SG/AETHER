import json
from typing import Any

from aether_backend.utils.effect import Program, Return
from aether_backend.utils.subagent import (
    InternalToolDependencies,
    internal_tool_registry,
)
from agents import RunContextWrapper, tool_context


async def test(service: Any, func_name: str, **kwargs) -> Program:
    ctx = RunContextWrapper(context=InternalToolDependencies(service))
    tool = internal_tool_registry.get_tool_by_name(func_name)
    if tool is not None:
        tool_ctx = tool_context.ToolContext(
            context=ctx.context,
            usage=ctx.usage,
            tool_name=tool.name,
            tool_arguments=json.dumps(kwargs),
            tool_call_id="manual-test-call"
        )

        output = await tool.on_invoke_tool(tool_ctx, json.dumps(kwargs))
        yield Return(output)
    else:
        yield Return("Tool does not exist")
