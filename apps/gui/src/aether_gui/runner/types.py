import asyncio
import queue
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TypeVar

T = TypeVar("T")


class TaskStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class TaskHandle:
    task_id: str
    status: TaskStatus = TaskStatus.PENDING
    error: BaseException | None = None
    _queue: queue.Queue = field(default_factory=queue.Queue)
    _done: asyncio.Event = field(default_factory=asyncio.Event)
