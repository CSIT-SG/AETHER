from functools import wraps

from rpyc import Service

from .capabilities.base import Capability
from .executors.base import IDAExecutor


class IDAService(Service):  # type: ignore[misc]
    def __init__(
        self,
        executor: IDAExecutor,
        capabilities: list[Capability],
    ) -> None:
        self._executor = executor

        for cap in capabilities:
            setattr(
                self,
                f"exposed_{cap.name}",
                self._wrap(cap),
            )

    def _wrap(self, cap: Capability):
        @wraps(cap.execute)
        def _handler(**kwargs):
            return self._executor.execute(
                cap.execute,
                kwargs,
            )

        return _handler
