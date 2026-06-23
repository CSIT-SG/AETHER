from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4


class PlanStatus(Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    ABANDONED = "abandoned"


class ActionStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class Action:
    description: str
    id: str = field(default_factory=lambda: str(uuid4()))
    status: ActionStatus = ActionStatus.PENDING
    sub_actions: list["Action"] = field(default_factory=list)
    parent_id: str | None = None
    result: str | None = None
    memory_refs: list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)
    error: str | None = None
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: datetime | None = None

    @property
    def steps(self) -> list["Action"]:
        return self.sub_actions

    def is_ready(self) -> bool:
        return self.status == ActionStatus.PENDING

    def get_effective_status(self) -> ActionStatus:
        if not self.sub_actions:
            return self.status

        all_completed = all(
            action.get_effective_status() in (ActionStatus.COMPLETED, ActionStatus.SKIPPED)
            for action in self.sub_actions
        )
        if all_completed:
            return ActionStatus.COMPLETED

        any_started = any(
            action.get_effective_status() in (ActionStatus.IN_PROGRESS, ActionStatus.COMPLETED)
            for action in self.sub_actions
        )
        if any_started or self.status == ActionStatus.IN_PROGRESS:
            return ActionStatus.IN_PROGRESS
        return ActionStatus.PENDING

    def mark_started(self) -> None:
        self.status = ActionStatus.IN_PROGRESS

    def mark_completed(self, result: str | None = None, memory_refs: list[str] | None = None) -> None:
        self.status = ActionStatus.COMPLETED
        self.completed_at = datetime.now()
        if result:
            self.result = result
        if memory_refs:
            self.memory_refs = list(memory_refs)

    def mark_failed(self, error: str) -> None:
        self.status = ActionStatus.FAILED
        self.error = error
        self.completed_at = datetime.now()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "status": self.status.value,
            "parent_id": self.parent_id,
            "sub_actions": [action.to_dict() for action in self.sub_actions],
            "result": self.result,
            "memory_refs": list(self.memory_refs),
            "depends_on": list(self.depends_on),
            "error": self.error,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Action":
        action = cls(
            id=data.get("id", str(uuid4())),
            description=data["description"],
            status=ActionStatus(data.get("status", "pending")),
            parent_id=data.get("parent_id"),
            result=data.get("result"),
            memory_refs=list(data.get("memory_refs", [])),
            depends_on=list(data.get("depends_on", [])),
            error=data.get("error"),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(),
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
        )
        action.sub_actions = [cls.from_dict(item) for item in data.get("sub_actions", [])]
        return action

    def summary(self, indent: int = 0) -> str:
        status_icon = {
            ActionStatus.PENDING: "○",
            ActionStatus.IN_PROGRESS: "→",
            ActionStatus.COMPLETED: "✓",
            ActionStatus.FAILED: "✗",
            ActionStatus.SKIPPED: "⊘",
        }.get(self.get_effective_status(), "?")
        prefix = "  " * (indent + 1)
        rendered = f"{prefix}{status_icon} [{self.id}] {self.description}"
        for sub_action in self.sub_actions:
            rendered += "\n" + sub_action.summary(indent + 1)
        return rendered


@dataclass
class Plan:
    goal: str
    id: str = field(default_factory=lambda: str(uuid4()))
    description: str = ""
    status: PlanStatus = PlanStatus.ACTIVE
    actions: list[Action] = field(default_factory=list)
    parent_plan_id: str | None = None
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def steps(self) -> list[Action]:
        return self.actions

    def add_action(
        self,
        description: str,
        depends_on: list[str] | None = None,
        index: int | None = None,
        parent_id: str | None = None,
    ) -> Action:
        action = Action(description=description, depends_on=list(depends_on or []), parent_id=parent_id)
        if parent_id:
            parent = self.get_action(parent_id)
            if parent is not None:
                if index is not None:
                    parent.sub_actions.insert(index, action)
                else:
                    parent.sub_actions.append(action)
                return action

        if index is not None:
            self.actions.insert(index, action)
        else:
            self.actions.append(action)
        return action

    def get_action(self, action_id: str) -> Action | None:
        def _find(actions: list[Action]) -> Action | None:
            for action in actions:
                if action.id == action_id:
                    return action
                found = _find(action.sub_actions)
                if found is not None:
                    return found
            return None

        return _find(self.actions)

    def iter_actions(self) -> list[Action]:
        flattened: list[Action] = []

        def _walk(actions: list[Action]) -> None:
            for action in actions:
                flattened.append(action)
                _walk(action.sub_actions)

        _walk(self.actions)
        return flattened

    def get_ready_actions(self) -> list[Action]:
        return [action for action in self.iter_actions() if action.is_ready()]

    def get_next_action(self) -> Action | None:
        def _find_next(actions: list[Action]) -> Action | None:
            for action in actions:
                status = action.get_effective_status()
                if status in (ActionStatus.COMPLETED, ActionStatus.SKIPPED):
                    continue
                if action.sub_actions:
                    next_sub = _find_next(action.sub_actions)
                    if next_sub is not None:
                        return next_sub
                if action.is_ready():
                    return action
            return None

        return _find_next(self.actions)

    def get_completed_actions(self) -> list[Action]:
        return [action for action in self.iter_actions() if action.status == ActionStatus.COMPLETED]

    def get_in_progress_actions(self) -> list[Action]:
        return [action for action in self.iter_actions() if action.get_effective_status() == ActionStatus.IN_PROGRESS]

    def is_complete(self) -> bool:
        actions = self.iter_actions()
        return bool(actions) and all(action.get_effective_status() in (ActionStatus.COMPLETED, ActionStatus.SKIPPED) for action in actions)

    def progress(self) -> tuple[int, int]:
        actions = self.iter_actions()
        total = len(actions)
        completed = sum(1 for action in actions if action.get_effective_status() in (ActionStatus.COMPLETED, ActionStatus.SKIPPED))
        return completed, total

    def progress_percent(self) -> float:
        completed, total = self.progress()
        return (completed / total * 100.0) if total else 0.0

    def mark_completed(self) -> None:
        self.status = PlanStatus.COMPLETED
        self.completed_at = datetime.now()

    def mark_abandoned(self) -> None:
        self.status = PlanStatus.ABANDONED
        self.completed_at = datetime.now()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "goal": self.goal,
            "description": self.description,
            "status": self.status.value,
            "actions": [action.to_dict() for action in self.actions],
            "parent_plan_id": self.parent_plan_id,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Plan":
        plan = cls(
            id=data.get("id", str(uuid4())),
            goal=data["goal"],
            description=data.get("description", ""),
            status=PlanStatus(data.get("status", "active")),
            parent_plan_id=data.get("parent_plan_id"),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(),
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
            metadata=dict(data.get("metadata", {})),
        )
        plan.actions = [Action.from_dict(action_data) for action_data in data.get("actions", [])]
        return plan

    def summary(self) -> str:
        return render_plan_for_prompt(self)


def _format_action_path(action: Action, plan: Plan | None = None) -> str:
    path = [action.description]
    current = action
    while current.parent_id and plan:
        parent = plan.get_action(current.parent_id)
        if parent is None:
            break
        path.insert(0, parent.description)
        current = parent
    return " > ".join(path)


def _status_icon(status: ActionStatus) -> str:
    return {
        ActionStatus.PENDING: "○",
        ActionStatus.IN_PROGRESS: "→",
        ActionStatus.COMPLETED: "✓",
        ActionStatus.FAILED: "✗",
        ActionStatus.SKIPPED: "⊘",
    }.get(status, "?")


def _format_action_tree(actions: list[Action], indent: int = 0) -> list[str]:
    lines: list[str] = []
    prefix = "  " * (indent + 1)
    for action in actions:
        status = action.get_effective_status()
        suffix_parts: list[str] = []
        if action.depends_on:
            suffix_parts.append(f"depends_on={', '.join(action.depends_on)}")
        if action.result and status == ActionStatus.COMPLETED:
            suffix_parts.append(f"result={action.result}")
        if action.error and status == ActionStatus.FAILED:
            suffix_parts.append(f"error={action.error}")
        suffix = f" ({'; '.join(suffix_parts)})" if suffix_parts else ""
        lines.append(f"{prefix}{_status_icon(status)} [{action.id}] {action.description}{suffix}")
        if action.sub_actions:
            lines.extend(_format_action_tree(action.sub_actions, indent + 1))
    return lines


def _format_focus_section(title: str, actions: list[Action], plan: Plan) -> list[str]:
    lines = [title]
    if not actions:
        lines.append("  (none)")
        return lines
    for action in actions:
        lines.append(f"  - [{action.id}] {_format_action_path(action, plan)}")
    return lines


def render_plan_for_prompt(plan: Plan) -> str:
    completed, total = plan.progress()
    next_actions = plan.get_ready_actions()[:3]
    recent_completed = plan.get_completed_actions()[-3:]

    lines = [
        "[ACTIVE PLAN]",
        f"Goal: {plan.goal}",
        f"Description: {plan.description or '(none)'}",
        f"Status: {plan.status.value.upper()} ({completed}/{total} actions complete, {plan.progress_percent():.0f}%)",
        "",
    ]
    lines.extend(_format_focus_section("Next Actions:", next_actions, plan))
    lines.append("")
    lines.extend(_format_focus_section("Recently Completed:", recent_completed, plan))
    lines.append("")
    lines.append("Action Tree:")
    lines.extend(_format_action_tree(plan.actions) or ["  (no actions)"])
    return "\n".join(lines)


class PlanManager:
    def __init__(self):
        self._plans: dict[str, Plan] = {}
        self._active_plan_id: str | None = None

    @property
    def active_plan(self) -> Plan | None:
        if self._active_plan_id:
            return self._plans.get(self._active_plan_id)
        return None

    @active_plan.setter
    def active_plan(self, value: Plan | dict[str, Any] | None) -> None:
        if value is None:
            self._active_plan_id = None
            return
        plan = Plan.from_dict(value) if isinstance(value, dict) else value
        self._plans[plan.id] = plan
        self._active_plan_id = plan.id

    @property
    def all_plans(self) -> list[Plan]:
        return list(self._plans.values())

    def create_plan(
        self,
        goal: str,
        actions: list[dict[str, Any]] | None = None,
        description: str = "",
        set_active: bool = True,
        index: int | None = None,
    ) -> Plan:
        plan = Plan(goal=goal, description=description)
        if actions:
            for action_data in actions:
                plan.add_action(
                    description=action_data.get("description", ""),
                    depends_on=action_data.get("depends_on"),
                )
        if index is None:
            self._plans[plan.id] = plan
        else:
            plans = self.all_plans
            plans.insert(max(0, min(index, len(plans))), plan)
            self._plans = {candidate.id: candidate for candidate in plans}
        if set_active:
            self._active_plan_id = plan.id
        return plan

    def set_active_plan(self, plan_id: str) -> bool:
        if plan_id in self._plans:
            self._active_plan_id = plan_id
            return True
        return False

    def get_next_action(self, plan: Plan | None = None) -> Action | None:
        plan = plan or self.active_plan
        return plan.get_next_action() if plan else None

    def complete_action(
        self,
        action: Action,
        result: str | None = None,
        memory_refs: list[str] | None = None,
        context_manager: Any | None = None,
    ) -> None:
        action.mark_completed(result=result, memory_refs=memory_refs)
        plan = self._get_plan_for_action(action.id)
        if plan and plan.is_complete():
            plan.mark_completed()
            if context_manager and hasattr(context_manager, "on_plan_completed"):
                context_manager.on_plan_completed(plan)

    def start_action(self, action: Action) -> None:
        action.mark_started()

    def fail_action(self, action: Action, error: str) -> None:
        action.mark_failed(error)

    def skip_action(self, action: Action) -> None:
        action.status = ActionStatus.SKIPPED
        action.completed_at = action.created_at

    def remove_action(self, plan: Plan, action_id: str) -> bool:
        action = plan.get_action(action_id)
        if action is None:
            return False
        if action.parent_id:
            parent = plan.get_action(action.parent_id)
            if parent is None:
                return False
            parent.sub_actions = [candidate for candidate in parent.sub_actions if candidate.id != action_id]
            return True
        plan.actions = [candidate for candidate in plan.actions if candidate.id != action_id]
        return True

    def add_action_to_plan(
        self,
        plan: Plan,
        description: str,
        depends_on: list[str] | None = None,
        after_action_id: str | None = None,
        parent_id: str | None = None,
    ) -> Action:
        index = None
        if after_action_id:
            actions_to_search = plan.actions
            if parent_id:
                parent = plan.get_action(parent_id)
                if parent:
                    actions_to_search = parent.sub_actions
            for i, action in enumerate(actions_to_search):
                if action.id == after_action_id:
                    index = i + 1
                    break

        return plan.add_action(
            description=description,
            depends_on=depends_on,
            index=index,
            parent_id=parent_id,
        )

    def adapt_plan(self, plan: Plan, new_actions: list[dict[str, Any]], insert_after: str | None = None) -> list[Action]:
        return [
            self.add_action_to_plan(
                plan=plan,
                description=action_data.get("description", ""),
                depends_on=action_data.get("depends_on"),
                after_action_id=insert_after,
            )
            for action_data in new_actions
        ]

    def create_sub_plan(self, parent_plan: Plan, goal: str, actions: list[dict[str, Any]]) -> Plan:
        sub_plan = self.create_plan(goal=goal, actions=actions, set_active=False)
        sub_plan.parent_plan_id = parent_plan.id
        return sub_plan

    def _get_plan_for_action(self, action_id: str) -> Plan | None:
        for plan in self._plans.values():
            if plan.get_action(action_id):
                return plan
        return None

    def get_plan(self, plan_id: str) -> Plan | None:
        return self._plans.get(plan_id)

    def remove_plan(self, plan_id: str) -> bool:
        if plan_id not in self._plans:
            return False
        del self._plans[plan_id]
        if self._active_plan_id == plan_id:
            self._active_plan_id = next(iter(self._plans), None)
        return True

    def clear(self) -> None:
        self._plans.clear()
        self._active_plan_id = None

    def get_all_memory_refs(self, plan: Plan | None = None) -> list[str]:
        plan = plan or self.active_plan
        if plan is None:
            return []
        refs: list[str] = []
        for action in plan.iter_actions():
            refs.extend(action.memory_refs)
        return refs

    def summary(self) -> str:
        if self.active_plan is None:
            return "No active plan."
        return self.active_plan.summary()
