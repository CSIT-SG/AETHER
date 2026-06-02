import asyncio
from functools import wraps

from rpyc import Service

from .capabilities.base import Capability
from .executors.base import IDAExecutor


class IDAService(Service):  # type: ignore[misc]
    """
    rpyc service layer. One instance per connection.

    rpyc calls exposed_* methods remotely. Each call is dispatched
    through the executor so the capability runs in the correct context
    (main thread for GUI, direct for headless).
    """

    def __init__(self, executor: IDAExecutor, capabilities: list[Capability]) -> None:
        self._executor = executor

        # we dynamically create an exposed_ method for each capability, which rpyc will call remotely by name.
        for cap in capabilities:
            setattr(self, f"exposed_{cap.name}", self._wrap(cap))

    def _wrap(self, cap: Capability):
        """Return a callable that runs cap.execute through the executor."""

        @wraps(cap.execute)  # preserves the signature rpyc reflects
        def _handler(**kwargs):
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            return loop.run_until_complete(self._executor.execute(cap.execute, kwargs))

        return _handler
