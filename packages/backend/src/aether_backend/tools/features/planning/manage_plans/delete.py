from aether_backend.tools.features.planning.store_singleton import get_plan_store
from aether_backend.utils.effect import Log, Program, Return


async def delete_plan_cb(plan_id: str) -> Program:
    plan_store = get_plan_store()
    await plan_store.delete(plan_id)
    yield Log(f"Deleted plan {plan_id!r}")
    yield Return({"plan_id": plan_id})
