from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from itertools import chain
from typing import Any, cast

from agents import Tool

from ..constants import SubagentTool


class SubagentToolRegistry:
    def __init__(self) -> None:
        self._registry: defaultdict[SubagentTool, list[Callable[..., Any]]] = defaultdict(list)

    def tag(self, *tools: SubagentTool) -> Callable[..., Any]:
        def decorator(func: Callable[..., Any]) -> Any:
            for tool in tools:
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

    def get_all_tools(self) -> list[Tool]:
        unique = set(chain.from_iterable(self._registry.values()))
        return cast(list[Tool], list(unique))


registry = SubagentToolRegistry()


@dataclass
class ToolDependencies:
    service: Any
