from __future__ import annotations

from abc import ABC
from collections.abc import Callable
from copy import deepcopy
import json
from typing import Any

from ..services.memory import MemoryPriority
from ..services.planning import Plan


AgentPlan = Plan


class RuntimeTool(ABC):
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description

    def clone(self) -> "RuntimeTool":
        return deepcopy(self)


class PlanningTool(RuntimeTool):
    def __init__(self):
        super().__init__(
            name="planning",
            description="Mandatory task planning tool for managing agent plans and step progress.",
        )

    def create_plan(self, ctx: "AgentContext", goal: str, actions: list[dict[str, Any]]) -> str:
        plan = ctx.plan_manager.create_plan(
            goal=goal,
            actions=actions,
            set_active=True,
        )
        action_list = "\n".join(f"  - [{action.id}] {action.description}" for action in plan.actions)
        return f"Plan created: {plan.goal}\n\nActions:\n{action_list}\n\nPlan details are now shown in your context."

    def update_plan(
        self,
        ctx: "AgentContext",
        add_actions: list[dict[str, Any]] | None = None,
        remove_action_ids: list[str] | None = None,
        start_action_ids: list[str] | None = None,
        complete_actions: list[dict[str, Any]] | None = None,
        fail_actions: list[dict[str, Any]] | None = None,
    ) -> str:
        plan = ctx.plan_manager.active_plan
        if not plan:
            return "Error: No active plan. Create a plan first using create_plan."

        updates = []

        if add_actions:
            for action_data in add_actions:
                created = ctx.plan_manager.add_action_to_plan(
                    plan=plan,
                    description=action_data.get("description", ""),
                    depends_on=action_data.get("depends_on"),
                    after_action_id=action_data.get("after_action_id"),
                    parent_id=action_data.get("parent_action_id"),
                )
                updates.append(f"Added: [{created.id}] {created.description}")

        if remove_action_ids:
            for action_id in remove_action_ids:
                if not ctx.plan_manager.remove_action(plan, action_id):
                    return f"Error: Action not found: {action_id}"
                updates.append(f"Removed: [{action_id}]")

        if start_action_ids:
            for action_id in start_action_ids:
                action = plan.get_action(action_id)
                if action is None:
                    return f"Error: Action not found: {action_id}"
                ctx.plan_manager.start_action(action)
                updates.append(f"Started: [{action.id}] {action.description}")

        if complete_actions:
            for item in complete_actions:
                action_id = item.get("action_id", "")
                action = plan.get_action(action_id)
                if action is None:
                    return f"Error: Action not found: {action_id}"
                ctx.plan_manager.complete_action(
                    action=action,
                    result=item.get("result"),
                    memory_refs=item.get("memory_refs"),
                )
                updates.append(f"Completed: [{action.id}] {action.description}")

        if fail_actions:
            for item in fail_actions:
                action_id = item.get("action_id", "")
                action = plan.get_action(action_id)
                if action is None:
                    return f"Error: Action not found: {action_id}"
                ctx.plan_manager.fail_action(action, item.get("error", ""))
                updates.append(f"Failed: [{action.id}] {action.description}")

        if not updates:
            return "No updates specified."

        completed, total = plan.progress()
        return f"Plan updated: {', '.join(updates)}\n\nProgress: {completed}/{total} actions complete"

    def delete_plan(self, ctx: "AgentContext", reason: str | None = None) -> str:
        plan = ctx.plan_manager.active_plan
        if not plan:
            return "No active plan to delete."

        plan.mark_abandoned()
        reason_str = f" Reason: {reason}" if reason else ""
        return f"Plan deleted: {plan.goal[:50]}...{reason_str}"


class ContextTool(RuntimeTool):
    def __init__(self):
        super().__init__(
            name="context",
            description="Mandatory context tool for per-agent working state.",
        )

    def get(self, ctx: "AgentContext", key: str, default: Any = None) -> Any:
        return ctx._runtime._agent_context[ctx.agent_id].get(key, default)

    def set(self, ctx: "AgentContext", key: str, value: Any) -> Any:
        ctx._runtime._agent_context[ctx.agent_id][key] = value
        return value

    def snapshot(self, ctx: "AgentContext") -> dict[str, Any]:
        return dict(ctx._runtime._agent_context[ctx.agent_id])


class MemoryTool(RuntimeTool):
    def __init__(self):
        super().__init__(
            name="memory",
            description="Mandatory memory tool backed by the shared backbone memory store.",
        )

    def _normalize_item(self, item: Any) -> dict[str, Any]:
        if isinstance(item, dict):
            payload = dict(item)
        else:
            payload = {
                "key": str(item),
                "value": str(item),
                "category": "runtime",
                "metadata": {"payload": item},
            }

        if "value" not in payload:
            if "result" in payload:
                payload["value"] = json.dumps(payload["result"], default=str)
            else:
                payload["value"] = json.dumps(payload, default=str)

        payload.setdefault("key", payload.get("type") or payload.get("task") or payload.get("objective") or "memory")
        payload.setdefault("category", payload.get("type") or "runtime")
        payload.setdefault("tags", [])
        metadata = dict(payload.get("metadata", {}))
        reserved = {"key", "value", "category", "priority", "tags", "metadata"}
        for key, value in payload.items():
            if key not in reserved:
                metadata[key] = value
        payload["metadata"] = metadata
        return payload

    def _coerce_priority(self, value: Any) -> MemoryPriority:
        if isinstance(value, MemoryPriority):
            return value
        if isinstance(value, str):
            try:
                return MemoryPriority[value.upper()]
            except KeyError:
                return MemoryPriority.MEDIUM
        return MemoryPriority.MEDIUM

    def remember(self, ctx: "AgentContext", item: Any) -> Any:
        payload = self._normalize_item(item)
        return ctx.memory_store.add_memory(
            key=payload.get("key"),
            value=payload.get("value"),
            category=payload.get("category", "runtime"),
            priority=self._coerce_priority(payload.get("priority")),
            tags=list(payload.get("tags", [])),
            metadata=dict(payload.get("metadata", {})),
        )

    def list_memories(self, ctx: "AgentContext") -> list[Any]:
        return list(ctx.memory_store.memories.values())

    def search_memories(self, ctx: "AgentContext", query: str, top_k: int = 5) -> list[Any]:
        return ctx.memory_store.search_memories(query, top_k=top_k)


class FunctionTool(RuntimeTool):
    def __init__(
        self,
        name: str,
        handler: Callable[..., Any],
        *,
        description: str = "",
    ):
        super().__init__(name=name, description=description)
        self._handler = handler

    def invoke(self, ctx: "AgentContext", *args: Any, **kwargs: Any) -> Any:
        return self._handler(ctx, *args, **kwargs)


class AgentToolbox:
    def __init__(self, ctx: "AgentContext"):
        self._ctx = ctx

    def names(self) -> list[str]:
        return sorted(self._ctx._runtime._agent_tools[self._ctx.agent_id].keys())

    def get(self, name: str) -> RuntimeTool | None:
        return self._ctx._runtime._agent_tools[self._ctx.agent_id].get(name)

    def require(self, name: str) -> RuntimeTool:
        tool = self.get(name)
        if tool is None:
            raise KeyError(f"Tool '{name}' is not available for agent '{self._ctx.agent_id}'.")
        return tool

    def __contains__(self, name: str) -> bool:
        return self.get(name) is not None

    def __getitem__(self, name: str) -> RuntimeTool:
        return self.require(name)


__all__ = [
    "AgentPlan",
    "AgentToolbox",
    "ContextTool",
    "FunctionTool",
    "MemoryTool",
    "PlanningTool",
    "RuntimeTool",
]
