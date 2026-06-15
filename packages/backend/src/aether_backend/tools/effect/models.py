from dataclasses import dataclass
from typing import Any, Literal


@dataclass
class Progress:
    current: int | float
    total: int | float
    message: str = ""


@dataclass
class Log:
    message: str
    level: Literal["debug", "info", "warning", "error"] = "info"


@dataclass
class Sleep:
    seconds: float


@dataclass
class Return:
    """Yield to return a value from the tool, terminating the stream."""

    value: Any = None
