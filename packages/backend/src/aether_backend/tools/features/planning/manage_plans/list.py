from aether_backend.tools.features.planning.store_singleton import get_plan_store
from aether_backend.tools.features.planning.utils import PlanStatus
from aether_backend.utils.effect import Log, Program, Return


async def list_plans_cb(status: PlanStatus | None = None) -> Program:
    plan_store = get_plan_store()
    plans = await plan_store.list(status=status)
    yield Log(f"Listed {len(plans)} plan(s)")
    yield Return([plan.model_dump(mode="json") for plan in plans])
