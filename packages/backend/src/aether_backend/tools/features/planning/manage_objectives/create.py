from aether_backend.tools.features.planning.models import ObjectiveModel
from aether_backend.tools.features.planning.store_singleton import get_plan_store
from aether_backend.tools.features.planning.utils import ObjectiveStatus
from aether_backend.utils.effect import Program, Progress, Return

from .constants import MAX_OBJECTIVES


async def create_objective_cb(
    plan_id: str,
    text: str,
    status: ObjectiveStatus | None = None,
) -> Program:
    plan_store = get_plan_store()
    plan = await plan_store.get(plan_id)
    if len(plan.objectives) >= MAX_OBJECTIVES:
        raise ValueError(
            f"Plan {plan_id!r} already has {len(plan.objectives)} objectives and the limit is "
            f"{MAX_OBJECTIVES}; delete an objective before adding another"
        )

    objective = ObjectiveModel(text=text, status=status or ObjectiveStatus.PENDING)
    plan.objectives = [*plan.objectives, objective]
    yield Progress(f"Created objective {objective.id!r} in plan {plan_id!r}")
    yield Return(objective.model_dump(mode="json"))
