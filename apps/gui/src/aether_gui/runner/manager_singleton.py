from .manager import WorkerManager

_shared_worker_manager: WorkerManager | None = None


def get_shared_worker_manager() -> WorkerManager:
    """Return the shared WorkerManager instance.

    Returns:
        Shared WorkerManager with the event filter installed.
    """
    global _shared_worker_manager
    if _shared_worker_manager is None:
        _shared_worker_manager = WorkerManager()
    return _shared_worker_manager
