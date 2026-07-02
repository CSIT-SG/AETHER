from __future__ import annotations

import asyncio

from .models import PlanModel
from .utils import PlanStatus


class PlanStore:
    def __init__(self) -> None:
        self._plans: dict[str, PlanModel] = {}
        self._lock = asyncio.Lock()

    async def create(
        self, title: str, description: str = "", status: PlanStatus = PlanStatus.ACTIVE
    ) -> PlanModel:
        plan = PlanModel(title=title, description=description, status=status)
        async with self._lock:
            self._plans[plan.id] = plan
        return plan

    async def get(self, plan_id: str) -> PlanModel:
        async with self._lock:
            return self._get_locked(plan_id)

    async def list(self, status: PlanStatus | None = None) -> list[PlanModel]:
        async with self._lock:
            plans = list(self._plans.values())
        return [p for p in plans if status is None or p.status == status]

    async def update(
        self,
        plan_id: str,
        title: str | None = None,
        description: str | None = None,
        status: PlanStatus | None = None,
    ) -> PlanModel:
        async with self._lock:
            plan = self._get_locked(plan_id)
            if title is not None:
                plan.title = title
            if description is not None:
                plan.description = description
            if status is not None:
                plan.status = status
            return plan

    async def delete(self, plan_id: str) -> None:
        async with self._lock:
            if plan_id not in self._plans:
                raise KeyError(f"Plan {plan_id!r} not found")
            del self._plans[plan_id]

    async def exists(self, plan_id: str) -> bool:
        async with self._lock:
            return plan_id in self._plans

    async def clear(self) -> None:
        async with self._lock:
            self._plans.clear()

    def _get_locked(self, plan_id: str) -> PlanModel:
        plan = self._plans.get(plan_id)
        if plan is None:
            raise KeyError(f"Plan {plan_id!r} not found")
        return plan
