import asyncio
from pathlib import Path

import yaml
from aether_benchmark.utils.task import Task
from pydantic import BaseModel, ValidationError


class ParseBenchmarkTask[T: BaseModel](Task[[T, Path], T]):  # type: ignore[misc]
    def __init__(self) -> None:
        self._cancelled = False

    async def start(self, schema: T, task_path: Path) -> T:
        """Load and validate a benchmark rubric YAML file."""
        self._cancelled = False

        if not task_path.exists():
            raise FileNotFoundError(f"Benchmark file not found: {task_path}")

        try:
            with task_path.open("r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
        except yaml.YAMLError as exc:  # pragma: no cover - exercised at runtime
            raise ValueError(f"Invalid YAML in benchmark file '{task_path}': {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError(
                f"Benchmark file '{task_path}' must contain a YAML object at the top level"
            )

        try:
            validated = schema.model_validate(data)
        except ValidationError as exc:
            raise ValueError(
                f"Benchmark schema validation failed for '{task_path}': {exc}"
            ) from exc

        if self._cancelled:
            raise asyncio.CancelledError("Benchmark parsing cancelled")

        return validated

    async def cancel(self) -> None:
        self._cancelled = True
