from pathlib import Path
from typing import Any

from aether_benchmark.utils.task import Task
from pydantic import BaseModel


class ParseBenchmarkTask(Task[[BaseModel, Path], dict[str, Any]]):  # type: ignore[misc]
    async def start(self, schema: BaseModel, task_path: Path) -> dict[str, Any]:
        # parse the yaml benchmark file, validate it and return the parsed object
        # use a typeddict as return value
        return {}

    async def cancel(self) -> None:
        # intentionally left blank, as this task does not have any long-running operations to cancel
        pass
