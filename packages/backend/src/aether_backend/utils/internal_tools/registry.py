from collections import defaultdict
from collections.abc import Callable
from typing import Any, Sequence
from agents import FunctionTool

from .constants import SubagentTool

_registry: defaultdict[SubagentTool, list[Callable[..., Any]]] = defaultdict(list)


def subagent_tool_tag(tool: SubagentTool) -> Callable[..., Any]:
    def decorator(func: Callable[..., Any]) -> Any:
        _registry[tool].append(func)
        return func

    return decorator


def get_subagent_tools(*tools: SubagentTool) -> Sequence[SubagentTool]:
    seen = set()
    for tool in tools:
        seen.update(_registry[tool])
    return list(seen)
