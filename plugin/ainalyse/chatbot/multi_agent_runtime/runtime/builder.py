from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .agent.base import CallbackAgent
from .core import MultiAgentRuntime
from ..tools import FunctionTool, RuntimeTool


AgentHandler = Callable[[CallbackAgent, Any, Any], None]
ToolFactory = Callable[..., RuntimeTool]
FunctionToolHandler = Callable[..., Any]


@dataclass(slots=True)
class ToolSpec:
    kind: str
    name: str | None = None
    description: str = ""
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AgentSpec:
    agent_id: str
    handler: str
    description: str = ""
    tools: list[ToolSpec] = field(default_factory=list)


class AgentBuilder:
    def __init__(self, runtime: MultiAgentRuntime):
        self.runtime = runtime
        self._handler_registry: dict[str, AgentHandler] = {}
        self._tool_registry: dict[str, ToolFactory] = {}
        self._function_tool_registry: dict[str, FunctionToolHandler] = {}

    def register_handler(self, name: str, handler: AgentHandler) -> "AgentBuilder":
        self._handler_registry[name] = handler
        return self

    def register_tool_factory(self, kind: str, factory: ToolFactory) -> "AgentBuilder":
        self._tool_registry[kind] = factory
        return self

    def register_function_tool(self, name: str, handler: FunctionToolHandler) -> "AgentBuilder":
        self._function_tool_registry[name] = handler
        return self

    def create_agent(
        self,
        agent_id: str,
        *,
        handler: AgentHandler,
        description: str = "",
        tools: Iterable[RuntimeTool] | None = None,
    ) -> CallbackAgent:
        return self.runtime.create_agent(
            agent_id,
            handler,
            description=description,
            tools=list(tools or ()),
        )

    def create_agent_from_spec(self, spec: AgentSpec | Mapping[str, Any]) -> CallbackAgent:
        if isinstance(spec, Mapping):
            spec = self._parse_agent_spec(spec)

        if spec.handler not in self._handler_registry:
            raise KeyError(f"Unknown handler '{spec.handler}'.")

        resolved_tools = [self._build_tool(tool_spec) for tool_spec in spec.tools]
        return self.create_agent(
            spec.agent_id,
            handler=self._handler_registry[spec.handler],
            description=spec.description,
            tools=resolved_tools,
        )

    def create_agents_from_config(self, config: dict[str, Any]) -> list[CallbackAgent]:
        agent_specs = [self._parse_agent_spec(agent_data) for agent_data in config.get("agents", [])]
        return [self.create_agent_from_spec(spec) for spec in agent_specs]

    def _parse_agent_spec(self, data: Mapping[str, Any]) -> AgentSpec:
        return AgentSpec(
            agent_id=data["agent_id"],
            handler=data["handler"],
            description=data.get("description", ""),
            tools=[
                self._parse_tool_spec(tool_data)
                for tool_data in data.get("tools", [])
            ],
        )

    def _parse_tool_spec(self, data: ToolSpec | Mapping[str, Any]) -> ToolSpec:
        if isinstance(data, ToolSpec):
            return data
        return ToolSpec(
            kind=data["kind"],
            name=data.get("name"),
            description=data.get("description", ""),
            params=dict(data.get("params", {})),
        )

    def _build_tool(self, spec: ToolSpec) -> RuntimeTool:
        if spec.kind == "function":
            if not spec.name:
                raise ValueError("Function tool specs require a tool name.")
            if spec.name not in self._function_tool_registry:
                raise KeyError(f"Unknown function tool '{spec.name}'.")
            return FunctionTool(
                spec.name,
                self._function_tool_registry[spec.name],
                description=spec.description,
            )

        if spec.kind not in self._tool_registry:
            raise KeyError(f"Unknown tool kind '{spec.kind}'.")

        factory = self._tool_registry[spec.kind]
        params = dict(spec.params)
        if spec.name is not None and "name" not in params:
            params["name"] = spec.name
        if spec.description and "description" not in params:
            params["description"] = spec.description
        return factory(**params)
