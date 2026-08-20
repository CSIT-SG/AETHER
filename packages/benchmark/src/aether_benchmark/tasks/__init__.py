from __future__ import annotations

from .evaluate import EvaluateTask
from .parse_benchmark import ParseBenchmarkTask

__all__ = ["EvaluateTask", "ParseBenchmarkTask", "StartRPCServerTask"]


def __getattr__(name: str) -> object:
    """Lazily import StartRPCServerTask on first access.

    Importing it eagerly would pull in ``aether_rpc.executors.headless_executor``,
    which imports ``idapro`` at module load — that requires an IDA install and
    fails during collection of tests that only need the other tasks.
    """
    if name == "StartRPCServerTask":
        from .start_rpc_server import StartRPCServerTask

        return StartRPCServerTask
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
