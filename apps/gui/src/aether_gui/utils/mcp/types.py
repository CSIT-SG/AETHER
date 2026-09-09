from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

type ServerLogListener = Callable[[str], Awaitable[None]]


class LogListenerRegistry(Protocol):
    """Log-dispatching client abstract"""

    _log_listeners: set[ServerLogListener]


@dataclass
class LogSubscription:
    """Handle for a log listener; call `.close()` to stop receiving logs."""

    client: LogListenerRegistry
    listener: ServerLogListener

    def close(self) -> None:
        self.client._log_listeners.discard(self.listener)
