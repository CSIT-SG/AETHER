from typing import NotRequired, TypedDict


class BenchmarkResult(TypedDict):
    benchmark_name: str
    benchmark_version: str
    entries: list[dict]
    score: float
    passed: int
    total: int
    weighted_score: float
    total_weight: NotRequired[float]
