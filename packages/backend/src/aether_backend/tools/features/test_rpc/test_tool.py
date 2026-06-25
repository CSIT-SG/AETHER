from typing import Any

from aether_backend.utils.effect import Program, Return
from aether_backend.utils.subagent import (
    InternalToolDependencies,
    internal_tool_registry,
)
from agents import RunContextWrapper


async def test(service: Any, func_name: str, **kwargs) -> Program:
    ctx = RunContextWrapper(context=InternalToolDependencies(service))
    tool = internal_tool_registry.get_callable(func_name)
    if tool is not None:
        output = await tool(ctx, **kwargs)
        yield Return(output)
    else:
        yield Return("Tool does not exist")
