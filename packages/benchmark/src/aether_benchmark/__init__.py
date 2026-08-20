from __future__ import annotations

from .tasks import EvaluateTask, ParseBenchmarkTask

__all__ = [
    "EvaluateTask",
    "ParseBenchmarkTask",
    "StartRPCServerTask",
]


def __getattr__(name: str) -> object:
    """Lazily import StartRPCServerTask to avoid pulling in idapro at import time."""
    if name == "StartRPCServerTask":
        from .tasks import StartRPCServerTask

        return StartRPCServerTask
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")