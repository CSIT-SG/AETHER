from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Callable

from .loop import AgentLoopExecutor
from ..context import ContextBudget, ContextManager
from ...services.memory import MemoryPriority, MemoryStore
from ...services.planning import Plan, PlanManager
from ...prompts import DEFAULT_CAPABILITY_PROMPT, DEFAULT_IDENTITY_PROMPT, PromptComposer, PromptConfig


SimplePlanManager = PlanManager


@dataclass
class BackboneCheckpoint:
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    session_id: str = ""
    total_tool_calls: int = 0
    total_memories: int = 0
    iterations_in_session: int = 0
    next_task: str | None = None
    agent_state: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BackboneCheckpoint":
        return cls(**data)

    def summary(self) -> str:
        return (
            f"Backbone Checkpoint ({self.timestamp})\n"
            f"Session: {self.session_id or 'N/A'}\n"
            f"Tool calls: {self.total_tool_calls}\n"
            f"Memories: {self.total_memories}\n"
            f"Next task: {self.next_task or 'None'}"
        )


class BackboneCheckpointManager:
    def __init__(self, export_state: Callable[[], dict[str, Any]], import_state: Callable[[dict[str, Any]], None]):
        self._export_state = export_state
        self._import_state = import_state

    def save_checkpoint(self, checkpoint: BackboneCheckpoint, filepath: str) -> str:
        payload = {"checkpoint": checkpoint.to_dict(), "state": self._export_state()}
        with open(filepath, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, default=str)
        return filepath

    def load_checkpoint(self, filepath: str) -> BackboneCheckpoint:
        with open(filepath, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        self._import_state(payload.get("state", {}))
        return BackboneCheckpoint.from_dict(payload["checkpoint"])


class GenericBackboneAgent:
    def __init__(
        self,
        *,
        system_prompt: str | None = None,
        prompt_config: PromptConfig | dict[str, Any] | None = None,
        client: Any = None,
        model: str | None = None,
        max_iterations: int = 20,
        memory_store: MemoryStore | None = None,
        plan_manager: PlanManager | None = None,
        context_manager: ContextManager | None = None,
        verbose_output_dir: str = "results",
    ):
        self.prompt_composer = PromptComposer()
        self.prompt_config = self._build_prompt_config(prompt_config)
        self.system_prompt = system_prompt or self.prompt_composer.compose(self.prompt_config)
        self.client = client
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
        self.max_iterations = max_iterations
        self.memory_store = memory_store or MemoryStore()
        self.plan_manager = plan_manager or PlanManager()
        self.context_manager = context_manager or ContextManager(budget=ContextBudget(), memory_store=self.memory_store)
        self.context_manager.set_plan_manager(self.plan_manager)
        self._checkpoint: BackboneCheckpoint | None = None
        self._session_id = ""
        self._initial_task: str | None = None
        self._registered_tools: list[dict[str, Any]] = []
        self._tool_handlers: dict[str, Callable[..., str]] = {}
        self.checkpoint_manager = BackboneCheckpointManager(self._export_state, self._import_state)

        self._register_core_tools()
        self.executor = AgentLoopExecutor(
            client=self.client,
            model=self.model,
            max_iterations=self.max_iterations,
            system_prompt=self.system_prompt,
            tools=self._registered_tools,
            tool_handlers=self._tool_handlers,
            context_manager=self.context_manager,
            plan_manager=self.plan_manager,
            memory_store=self.memory_store,
            verbose_output_dir=verbose_output_dir,
        )

    def _build_prompt_config(self, prompt_config: PromptConfig | dict[str, Any] | None) -> PromptConfig:
        if prompt_config is None:
            return PromptConfig(identity=DEFAULT_IDENTITY_PROMPT, capability=DEFAULT_CAPABILITY_PROMPT)
        if isinstance(prompt_config, PromptConfig):
            return prompt_config
        return PromptConfig(
            identity=prompt_config.get("identity", DEFAULT_IDENTITY_PROMPT),
            capability=prompt_config.get("capability", DEFAULT_CAPABILITY_PROMPT),
            output_format=prompt_config.get("output_format", ""),
            runtime_appendix=prompt_config.get("runtime_appendix", ""),
            extra_sections=list(prompt_config.get("extra_sections", [])),
        )

    @property
    def tools(self) -> list[dict[str, Any]]:
        return list(self._registered_tools)

    @property
    def tool_handlers(self) -> dict[str, Callable[..., str]]:
        return dict(self._tool_handlers)

    def register_tool(
        self,
        *,
        name: str,
        description: str,
        parameters: dict[str, Any],
        handler: Callable[..., str],
    ) -> None:
        if name in self._tool_handlers:
            raise ValueError(f"Tool '{name}' is already registered.")
        self._registered_tools.append(
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": description,
                    "parameters": parameters,
                },
            }
        )
        self._tool_handlers[name] = handler

    def _register_core_tools(self) -> None:
        self.register_tool(
            name="create_plan",
            description="Create a new action plan.",
            parameters={
                "type": "object",
                "properties": {
                    "goal": {"type": "string"},
                    "actions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "description": {"type": "string"},
                                "depends_on": {"type": "array", "items": {"type": "string"}},
                            },
                            "required": ["description"],
                        },
                    },
                },
                "required": ["goal", "actions"],
            },
            handler=self.create_plan,
        )
        self.register_tool(
            name="update_plan",
            description="Update the current plan.",
            parameters={
                "type": "object",
                "properties": {
                    "add_actions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "description": {"type": "string"},
                                "parent_action_id": {"type": "string"},
                                "after_action_id": {"type": "string"},
                                "depends_on": {"type": "array", "items": {"type": "string"}},
                            },
                            "required": ["description"],
                        },
                    },
                    "remove_action_ids": {"type": "array", "items": {"type": "string"}},
                    "start_action_ids": {"type": "array", "items": {"type": "string"}},
                    "complete_actions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "action_id": {"type": "string"},
                                "result": {"type": "string"},
                                "memory_refs": {"type": "array", "items": {"type": "string"}},
                            },
                            "required": ["action_id"],
                        },
                    },
                    "fail_actions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "action_id": {"type": "string"},
                                "error": {"type": "string"},
                            },
                            "required": ["action_id", "error"],
                        },
                    },
                },
            },
            handler=self.update_plan,
        )
        self.register_tool(
            name="delete_plan",
            description="Delete the current plan.",
            parameters={"type": "object", "properties": {"reason": {"type": "string"}}},
            handler=self.delete_plan,
        )
        self.register_tool(
            name="add_memory",
            description="Store a finding in memory.",
            parameters={
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                    "value": {"type": "string"},
                    "category": {"type": "string"},
                    "priority": {"type": "string"},
                    "tags": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["key", "value", "category"],
            },
            handler=self.add_memory,
        )
        self.register_tool(
            name="add_memory_auto",
            description="Store a finding in memory with automatic node placement.",
            parameters={
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                    "value": {"type": "string"},
                    "category": {"type": "string"},
                    "priority": {"type": "string"},
                    "tags": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["key", "value", "category"],
            },
            handler=self.add_memory_auto,
        )
        self.register_tool(
            name="search_memories",
            description="Search stored memories.",
            parameters={
                "type": "object",
                "properties": {"query": {"type": "string"}, "top_k": {"type": "integer", "default": 5}},
                "required": ["query"],
            },
            handler=self.search_memories,
        )
        self.register_tool(
            name="get_context_statistics",
            description="Get current context statistics.",
            parameters={"type": "object", "properties": {}},
            handler=self.get_context_statistics_tool,
        )
        self.register_tool(
            name="get_memory_statistics",
            description="Get current memory statistics.",
            parameters={"type": "object", "properties": {}},
            handler=self.get_memory_statistics_tool,
        )

    def create_plan(self, goal: str, actions: list[dict[str, Any]]) -> str:
        plan = self.plan_manager.create_plan(goal=goal, actions=actions, set_active=True)
        action_list = "\n".join(
            f"  - [{action.id}] {action.description}" for action in plan.actions
        )
        return f"Plan created: {plan.goal}\n\nActions:\n{action_list}\n\nPlan details are now shown in your context."

    def update_plan(
        self,
        add_actions: list[dict[str, Any]] | None = None,
        remove_action_ids: list[str] | None = None,
        start_action_ids: list[str] | None = None,
        complete_actions: list[dict[str, Any]] | None = None,
        fail_actions: list[dict[str, Any]] | None = None,
    ) -> str:
        plan = self.plan_manager.active_plan
        if not plan:
            return "Error: No active plan. Create a plan first using create_plan."
        updates: list[str] = []
        if add_actions:
            for item in add_actions:
                created = self.plan_manager.add_action_to_plan(
                    plan=plan,
                    description=item.get("description", ""),
                    depends_on=item.get("depends_on"),
                    after_action_id=item.get("after_action_id"),
                    parent_id=item.get("parent_action_id"),
                )
                updates.append(f"Added: [{created.id}] {created.description}")
        if remove_action_ids:
            for action_id in remove_action_ids:
                if not self.plan_manager.remove_action(plan, action_id):
                    return f"Error: Action not found: {action_id}"
                updates.append(f"Removed: [{action_id}]")
        if start_action_ids:
            for action_id in start_action_ids:
                action = plan.get_action(action_id)
                if action is None:
                    return f"Error: Action not found: {action_id}"
                self.plan_manager.start_action(action)
                updates.append(f"Started: [{action.id}] {action.description}")
        if complete_actions:
            for item in complete_actions:
                action_id = item.get("action_id", "")
                action = plan.get_action(action_id)
                if action is None:
                    return f"Error: Action not found: {action_id}"
                self.plan_manager.complete_action(
                    action=action,
                    result=item.get("result"),
                    memory_refs=item.get("memory_refs"),
                    context_manager=self.context_manager,
                )
                updates.append(f"Completed: [{action.id}] {action.description}")
        if fail_actions:
            for item in fail_actions:
                action_id = item.get("action_id", "")
                action = plan.get_action(action_id)
                if action is None:
                    return f"Error: Action not found: {action_id}"
                error = item.get("error", "")
                self.plan_manager.fail_action(action, error)
                updates.append(f"Failed: [{action.id}] {action.description}")
        if not updates:
            return "No updates specified."
        completed, total = plan.progress()
        return f"Plan updated: {', '.join(updates)}\n\nProgress: {completed}/{total} actions complete"

    def delete_plan(self, reason: str | None = None) -> str:
        plan = self.plan_manager.active_plan
        if not plan:
            return "No active plan to delete."
        plan.mark_abandoned()
        reason_str = f" Reason: {reason}" if reason else ""
        return f"Plan deleted: {plan.goal[:50]}...{reason_str}"

    def add_memory(
        self,
        key: str,
        value: str,
        category: str,
        priority: str = "MEDIUM",
        tags: list[str] | None = None,
    ) -> str:
        try:
            priority_enum = MemoryPriority[priority.upper()]
        except KeyError:
            priority_enum = MemoryPriority.MEDIUM
        item = self.memory_store.add_memory(
            key=key,
            value=value,
            category=category,
            priority=priority_enum,
            tags=list(tags or []),
        )
        return f"Memory stored successfully (ID: {item.id}, Category: {category}, Priority: {priority_enum.name})"

    def add_memory_auto(
        self,
        key: str,
        value: str,
        category: str,
        priority: str = "MEDIUM",
        tags: list[str] | None = None,
    ) -> str:
        try:
            priority_enum = MemoryPriority[priority.upper()]
        except KeyError:
            priority_enum = MemoryPriority.MEDIUM
        item = self.memory_store.add_memory_auto(
            key=key,
            value=value,
            category=category,
            llm_client=None,
            priority=priority_enum,
            tags=list(tags or []),
        )
        return f"Memory stored successfully (ID: {item.id}, Category: {category}, Priority: {priority_enum.name})"

    def search_memories(self, query: str, top_k: int = 5) -> str:
        results = self.memory_store.search_memories(query, top_k=top_k)
        if not results:
            return f"No memories found matching: {query}"
        lines = [f"Found {len(results)} memories for '{query}':"]
        for index, item in enumerate(results, start=1):
            memory = item.memory
            lines.append(
                f"{index}. [{memory.category}] {memory.key} (memory_id={memory.id}): {memory.get_display_content()}"
            )
            lines.append(f"   Priority: {memory.priority.name}, Relevance: {item.relevance_score:.2f}")
            if item.reason:
                lines.append(f"   Reason: {item.reason}")
        return "\n".join(lines)

    def get_context_statistics_tool(self) -> str:
        return json.dumps(self.context_manager.get_statistics(), indent=2, default=str)

    def get_memory_statistics_tool(self) -> str:
        return json.dumps(self.memory_store.get_statistics(), indent=2, default=str)

    def create_checkpoint(self, next_task: str | None = None) -> BackboneCheckpoint:
        self._checkpoint = BackboneCheckpoint(
            session_id=self._session_id,
            total_tool_calls=len(self.context_manager.tool_buffer.records),
            total_memories=self.memory_store.get_statistics()["total_memories"],
            next_task=next_task,
            agent_state={
                "initial_task": self._initial_task,
                "plan": self.plan_manager.active_plan.to_dict() if self.plan_manager.active_plan else None,
            },
        )
        return self._checkpoint

    def load_checkpoint(self, filepath: str) -> BackboneCheckpoint:
        self._checkpoint = self.checkpoint_manager.load_checkpoint(filepath)
        self._initial_task = self._checkpoint.agent_state.get("initial_task")
        self.plan_manager.active_plan = self._checkpoint.agent_state.get("plan")
        return self._checkpoint

    def get_resume_prompt(self) -> str:
        if self._checkpoint is None:
            return ""
        return self._checkpoint.next_task or self._initial_task or "Continue the task."

    def run(
        self,
        task: str | None = None,
        checkpoint: BackboneCheckpoint | None = None,
        checkpoint_file: str | None = None,
        use_resume_prompt: bool = True,
    ) -> dict[str, Any]:
        if checkpoint_file:
            self.load_checkpoint(checkpoint_file)
            if use_resume_prompt:
                task = self.get_resume_prompt()
        elif checkpoint:
            self._checkpoint = checkpoint
            self._initial_task = checkpoint.agent_state.get("initial_task")
            self.plan_manager.active_plan = checkpoint.agent_state.get("plan")
            if use_resume_prompt:
                task = self.get_resume_prompt()
        task = task or "Work on the current goal."
        if self._initial_task is None:
            self._initial_task = task
        result = self.executor.run(task, self._checkpoint)
        self.create_checkpoint()
        result["checkpoint"] = self._checkpoint
        result["session_id"] = self._session_id
        return result

    def _export_state(self) -> dict[str, Any]:
        return {
            "memory_store": self.memory_store.export_to_dict(),
            "plan": self.plan_manager.active_plan.to_dict() if self.plan_manager.active_plan else None,
            "context": {
                "session_summary": getattr(self.context_manager, "_session_summary", ""),
                "checkpoint_summary": getattr(self.context_manager, "_checkpoint_summary", ""),
            },
        }

    def _import_state(self, state: dict[str, Any]) -> None:
        self.memory_store.import_from_dict(state.get("memory_store", {}))
        self.plan_manager.active_plan = state.get("plan")
        self.context_manager.set_session_summary(state.get("context", {}).get("session_summary", ""))
        self.context_manager.set_checkpoint_summary(state.get("context", {}).get("checkpoint_summary", ""))
