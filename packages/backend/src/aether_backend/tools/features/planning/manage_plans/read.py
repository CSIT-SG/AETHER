from aether_backend.tools.features.planning.store_singleton import get_plan_store
from aether_backend.utils.effect import Log, Program, Return


async def read_plan_cb(plan_id: str) -> Program:
    plan_store = get_plan_store()
    plan = await plan_store.get(plan_id)
    yield Log(f"Loaded plan {plan.id!r}")
    yield Return(plan.model_dump(mode="json"))
