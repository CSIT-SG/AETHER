from collections import defaultdict
from collections.abc import Callable
from typing import Any

from ..constants import SubagentTool


class SubagentToolRegistry:
    def __init__(self) -> None:
        self._registry: defaultdict[SubagentTool, list[Callable[..., Any]]] = defaultdict(list)

    def tag(self, tool: SubagentTool) -> Callable[..., Any]:
        def decorator(func: Callable[..., Any]) -> Any:
            self._registry[tool].append(func)
            return func
        return decorator

    def get_tools(self, *tools: SubagentTool) -> list[Callable[..., Any]]:
        seen: set[Callable[..., Any]] = set()
        for tool in tools:
            seen.update(self._registry[tool])
        return list(seen)