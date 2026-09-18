import asyncio
import enum
import threading
from concurrent.futures import Future
from dataclasses import dataclass, field
from queue import Queue
from typing import Any, NamedTuple

from .base_task import BaseTask


class _Sentinel(enum.Enum):
    TOKEN = enum.auto()


SENTINEL = _Sentinel.TOKEN


@dataclass
class TaskHandle[T]:
    task_id: str
    results: Queue[T | _Sentinel] = field(default_factory=Queue)
    done: threading.Event = field(default_factory=threading.Event)
    error: BaseException | None = None
    aio_task: asyncio.Task[None] | None = field(default=None, repr=False)


class TaskRecord(NamedTuple):
    task: BaseTask[Any]
    future: Future[None]
    handle: TaskHandle[Any]
