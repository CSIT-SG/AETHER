from .store import PlanStore

_plan_store: PlanStore | None = None


def get_plan_store() -> PlanStore:
    global _plan_store
    if _plan_store is None:
        _plan_store = PlanStore()
    return _plan_store


def reset_plan_store() -> PlanStore:
    global _plan_store
    _plan_store = PlanStore()
    return _plan_store
