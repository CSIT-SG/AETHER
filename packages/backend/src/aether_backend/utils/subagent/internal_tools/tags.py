from collections import defaultdict
from collections.abc import Callable
from typing import Any, cast

from agents import Tool

from ..constants import SubagentTool


class SubagentToolRegistry:
    def __init__(self) -> None:
        self._registry: defaultdict[SubagentTool, list[Callable[..., Any]]] = defaultdict(list)

    def tag(self, tool: SubagentTool) -> Callable[..., Any]:
        def decorator(func: Callable[..., Any]) -> Any:
            self._registry[tool].append(func)
            return func

        return decorator

    def get_tools(self, *tools: SubagentTool) -> list[Tool]:
        seen = []
        for tool in tools:
            for t in self._registry[tool]:
                if t not in seen:
                    seen.append(t)
        return cast(list[Tool], seen)
