from aether_backend.tools.features.planning.store_singleton import get_plan_store
from aether_backend.tools.features.planning.utils import PlanStatus
from aether_backend.utils.effect import Log, Program, Return


async def create_plan_cb(
    title: str,
    description: str | None = None,
    status: PlanStatus | None = None,
) -> Program:
    plan_store = get_plan_store()
    plan = await plan_store.create(
        title=title,
        description=description or "",
        status=status or PlanStatus.ACTIVE,
    )
    yield Log(f"Created plan {plan.id!r}")
    yield Return(plan.model_dump(mode="json"))
