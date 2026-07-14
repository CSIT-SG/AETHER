from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from itertools import chain
from typing import cast

from aether_backend.utils.get_rpc_service import AnyService
from agents import FunctionTool, Tool

from ..constants import SubagentTool


@dataclass
class ToolDependencies:
    service: AnyService


class SubagentToolRegistry:
    def __init__(self) -> None:
        self._registry: defaultdict[SubagentTool, list[FunctionTool]] = defaultdict(list)

    def tag(self, *tools: SubagentTool) -> Callable[[FunctionTool], FunctionTool]:
        def decorator(func: FunctionTool) -> FunctionTool:
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
        seen: list[FunctionTool] = []
        for tool in chain.from_iterable(self._registry.values()):
            if tool not in seen:
                seen.append(tool)
        return cast(list[Tool], seen)

    def get_tool_by_name(self, name: str) -> FunctionTool | None:
        for tool in chain.from_iterable(self._registry.values()):
            if tool.name == name:
                return tool
        return None


registry = SubagentToolRegistry()
