from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from itertools import chain
from typing import Any, cast

from agents import Tool, FunctionTool

from ..constants import SubagentTool


class SubagentToolRegistry:
    def __init__(self) -> None:
        self._registry: defaultdict[SubagentTool, list[FunctionTool]] = defaultdict(list)
        self._callables: dict[str, FunctionTool] = defaultdict()

    def tag(self, *tools: SubagentTool) -> Callable[..., Any]:
        def decorator(func: FunctionTool) -> Any:
            for tool in tools:
                self._registry[tool].append(func)

            self._add_callable(func)
            return func

        return decorator

    def _add_callable(self, func: FunctionTool) -> None:
        if func.name not in self._callables:
            self._callables[func.name] = func

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

    def get_callable(self, name: str) -> FunctionTool | None:
        if name not in self._callables:
            return None

        return self._callables[name]

    def get_all_callables(self) -> list[FunctionTool]:
        return list(self._callables.values())


registry = SubagentToolRegistry()


@dataclass
class ToolDependencies:
    service: Any
