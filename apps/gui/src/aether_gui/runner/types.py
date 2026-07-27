import enum
import threading
from dataclasses import dataclass, field
from queue import Queue


class _Sentinel(enum.Enum):
    TOKEN = enum.auto()


SENTINEL = _Sentinel.TOKEN


@dataclass
class TaskHandle[T]:
    task_id: str
    results: Queue[T | _Sentinel] = field(default_factory=Queue)
    done: threading.Event = field(default_factory=threading.Event)
    error: BaseException | None = None
