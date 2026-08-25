from pathlib import Path
from typing import NotRequired, TypedDict


class BenchmarkInput(TypedDict):
    kind: str
    idb: NotRequired[Path | None]
    doc: NotRequired[Path | None]
    ida_dir: NotRequired[Path | None]


class BenchmarkResult(TypedDict):
    benchmark_name: str
    benchmark_version: str
    entries: list[dict]
    score: float
    passed: int
    total: int
    weighted_score: float
    total_weight: NotRequired[float]
