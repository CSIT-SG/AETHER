import json
from dataclasses import asdict, dataclass
from typing import Literal


@dataclass
class Ok[T]:
    result: T
    success: Literal[True] = True

    def __str__(self) -> str:
        return json.dumps(asdict(self))


@dataclass
class Err:
    result: str
    success: Literal[False] = False

    def __str__(self) -> str:
        return json.dumps(asdict(self))


type Result[T] = Ok[T] | Err
