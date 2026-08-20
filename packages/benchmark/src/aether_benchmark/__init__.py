from __future__ import annotations

from .tasks import EvaluateTask, ParseBenchmarkTask

__all__ = [
    "EvaluateTask",
    "ParseBenchmarkTask",
    "StartRPCServerTask",
]


def __getattr__(name: str) -> object:
    """Lazily import StartRPCServerTask """
    if name == "StartRPCServerTask":
        from .tasks import StartRPCServerTask

        return StartRPCServerTask
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def main() -> None:
    """Run the benchmark CLI from ``python -m aether_benchmark``."""
    from .__main__ import main as _cli_main

    _cli_main()


if __name__ == "__main__":
    main()