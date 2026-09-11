from aether_backend.tools.features.planning.store_singleton import get_plan_store
from aether_backend.tools.features.planning.utils import PlanStatus
from aether_backend.utils.effect import Program, Progress, Return

from .constants import MAX_PLANS


async def create_plan_cb(
    title: str,
    description: str | None = None,
    status: PlanStatus | None = None,
) -> Program:
    plan_store = get_plan_store()
    plans = await plan_store.list()
    if len(plans) >= MAX_PLANS:
        raise ValueError(
            f"{len(plans)} plans already exist and the limit is {MAX_PLANS}; "
            "delete a completed or archived plan (list with a status to find them) "
            "before creating another"
        )

    plan = await plan_store.create(
        title=title,
        description=description or "",
        status=status or PlanStatus.ACTIVE,
    )
    yield Progress(f"Created plan {plan.id!r}")
    yield Return(plan.model_dump(mode="json"))
