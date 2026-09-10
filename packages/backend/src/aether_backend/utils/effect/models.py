from dataclasses import dataclass
from typing import Any


@dataclass
class Progress:
    message: str = ""


@dataclass
class Sleep:
    seconds: float


@dataclass
class Return:
    """Yield to return a value from the tool, terminating the stream."""

    value: Any = None
