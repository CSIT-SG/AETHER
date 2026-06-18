from collections import defaultdict
from collections.abc import Callable
from functools import wraps
from typing import Any

from .constants import SubagentTool

_registry: defaultdict[SubagentTool, list[Callable[..., Any]]] = defaultdict(list)


def subagent_tool_tag(tool: SubagentTool) -> Callable[..., Any]:
    @wraps(tool)  # type: ignore
    def decorator(func: Callable[..., Any]) -> Any:
        _registry[tool].append(func)
        return func

    return decorator


def get_subagent_tools(*tools: SubagentTool) -> list[Callable[..., Any]]:
    seen: set[Callable[..., Any]] = set()
    for tool in tools:
        seen.update(_registry[tool])
    return list(seen)
