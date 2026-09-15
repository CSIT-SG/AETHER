from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol


@dataclass
class ServerProgressMessage:
    """Server progress notification, abstracted from the MCP transport."""

    message: str | None
    progress: float
    total: float | None = None


type ServerProgressListener = Callable[[ServerProgressMessage], Awaitable[None]]


class ProgressListenerRegistry(Protocol):
    """Progress-dispatching client abstract"""

    _progress_listeners: set[ServerProgressListener]


@dataclass
class ProgressSubscription:
    """Handle for a progress listener. Call `.close()` to stop receiving logs."""

    client: ProgressListenerRegistry
    listener: ServerProgressListener

    def close(self) -> None:
        self.client._progress_listeners.discard(self.listener)
