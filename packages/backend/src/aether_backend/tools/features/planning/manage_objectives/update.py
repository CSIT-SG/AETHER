from aether_backend.tools.features.planning.store_singleton import get_plan_store
from aether_backend.tools.features.planning.utils import ObjectiveStatus
from aether_backend.utils.effect import Program, Progress, Return


async def update_objective_cb(
    plan_id: str,
    objective_id: str,
    text: str | None = None,
    status: ObjectiveStatus | None = None,
) -> Program:
    plan_store = get_plan_store()
    plan = await plan_store.get(plan_id)
    objective = next((item for item in plan.objectives if item.id == objective_id), None)
    if objective is None:
        raise KeyError(f"Objective {objective_id!r} not found in plan {plan_id!r}")
    if text is not None:
        objective.text = text
    if status is not None:
        objective.status = status
    yield Progress(f"Updated objective {objective.id!r} in plan {plan_id!r}")
    yield Return(objective.model_dump(mode="json"))
