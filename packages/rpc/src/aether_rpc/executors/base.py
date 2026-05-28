from abc import ABC, abstractmethod
from typing import Any
from aether_rpc.capabilities import Capability


class IDAExecutor(ABC):
    """Runs IDA operations. Impl decides whether that's GUI or headless."""

    @abstractmethod
    async def execute(self, capability: Capability, arguments: dict[str, Any]) -> Any:
        """Dispatch a single IDA operation by method name."""

    @abstractmethod
    async def startup(self) -> None:
        """Called once when the RPC server starts."""

    @abstractmethod
    async def shutdown(self) -> None:
        """Called once when the RPC server stops."""
