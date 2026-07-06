from collections.abc import Callable, Coroutine
from typing import Any
import asyncio

from watchdog.events import (
    DirCreatedEvent,
    DirDeletedEvent,
    DirMovedEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileMovedEvent,
    FileSystemEventHandler,
)


class RPCDiscoveryListener(FileSystemEventHandler):
    def __init__(self, callback : Callable[[], Coroutine[Any, Any, None]]) -> None:
        super().__init__()
        self.callback: Callable[[], Coroutine[Any, Any, None]] = callback

    def on_moved(self, event: DirMovedEvent | FileMovedEvent) -> None:
        asyncio.run(self.callback())
        print(f"RPCDiscoveryListener: Move Detected: {event.src_path!r} to {event.dest_path!r}")
        return None

    def on_created(self, event: DirCreatedEvent | FileCreatedEvent) -> None:
        self.callback()
        print(f"RPCDiscoveryListener: Creation Detected: {event.src_path!r}")
        return

    def on_deleted(self, event: DirDeletedEvent | FileDeletedEvent) -> None:
        self.callback()
        print(f"RPCDiscoveryListener: Deletion Detected: {event.src_path!r}")
        return
