from aether_backend.tools.features.planning.store_singleton import get_plan_store
from aether_backend.tools.features.planning.utils import PlanStatus
from aether_backend.utils.effect import Log, Program, Return


async def update_plan_cb(
    plan_id: str,
    title: str | None = None,
    description: str | None = None,
    status: PlanStatus | None = None,
) -> Program:
    plan_store = get_plan_store()
    plan = await plan_store.update(
        plan_id=plan_id,
        title=title,
        description=description,
        status=status,
    )
    yield Log(f"Updated plan {plan.id!r}")
    yield Return(plan.model_dump(mode="json"))
