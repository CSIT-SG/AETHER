import json
from dataclasses import asdict, dataclass


@dataclass
class Result:
    success: bool
    result: dict

    def __str__(self) -> str:
        return json.dumps(asdict(self))
