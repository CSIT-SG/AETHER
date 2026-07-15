import threading
from dataclasses import dataclass, field
from queue import Queue


@dataclass
class TaskHandle:
    task_id: str
    results: Queue = field(default_factory=Queue)
    done: threading.Event = field(default_factory=threading.Event)
    error: BaseException | None = None
