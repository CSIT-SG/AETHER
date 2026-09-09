from aether_backend.tools.features.planning.store_singleton import get_plan_store
from aether_backend.utils.effect import Program, Progress, Return


async def delete_objective_cb(plan_id: str, objective_id: str) -> Program:
    plan_store = get_plan_store()
    plan = await plan_store.get(plan_id)
    objectives = [objective for objective in plan.objectives if objective.id != objective_id]
    if len(objectives) == len(plan.objectives):
        raise KeyError(f"Objective {objective_id!r} not found in plan {plan_id!r}")
    plan.objectives = objectives
    yield Progress(f"Deleted objective {objective_id!r} from plan {plan_id!r}")
    yield Return({"plan_id": plan_id, "objective_id": objective_id})
