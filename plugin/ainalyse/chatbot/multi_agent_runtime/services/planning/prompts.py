"""
Prompt helpers for rendering plans in LLM context.
"""

from __future__ import annotations

from typing import Optional

from .plan import Action, Plan, render_plan_for_prompt


def format_plan_for_prompt(
    plan: Optional[Plan],
    max_in_progress: Optional[int] = None,
    max_completed: Optional[int] = None,
    max_pending: Optional[int] = None,
) -> str:
    del max_in_progress, max_completed, max_pending
    if plan is None:
        return ""
    return render_plan_for_prompt(plan)


def format_plan_summary_short(plan: Optional[Plan]) -> str:
    if plan is None:
        return ""

    completed, total = plan.progress()
    in_progress = len(plan.get_in_progress_actions())
    return f"[Plan: {plan.goal[:30]}... | {completed}/{total} | In Progress: {in_progress}]"


def format_action_for_memory(action: Action) -> dict:
    return {
        "action_id": action.id,
        "description": action.description,
        "status": action.status.value,
        "result": action.result,
        "memory_refs": action.memory_refs,
    }
