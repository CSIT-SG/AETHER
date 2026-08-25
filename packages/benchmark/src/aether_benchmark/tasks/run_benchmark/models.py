from pathlib import Path
from typing import NotRequired, TypedDict


class BenchmarkInput(TypedDict):

    kind: str
    idb: NotRequired[Path]
    doc: NotRequired[Path]
    ida_dir: NotRequired[Path]


class BenchmarkResult(TypedDict):

    benchmark_name: str
    benchmark_version: str
    entries: list[dict]
    score: float
    passed: int
    total: int
    weighted_score: float
    total_weight: NotRequired[float]
